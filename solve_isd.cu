#include <iostream>
#include <vector>
#include <fstream>
#include <cstdint>
#include <random>
#include <algorithm>
#include <cuda_runtime.h>

// --- Simplified BitVec for CUDA interoperability ---
// On Device, we treat BitVec as raw uint64_t array.
// Matrix M: K rows, (K+1) bits wide.
// Packed: K rows, ceil((K+1)/64) words per row.

// Parameters
constexpr int LPN_N = 4096; // K
constexpr int LPN_T = 16384; // N (samples)
constexpr int M_BITS = 8192; // Original K, but we use LPN_N
constexpr int WORDS_PER_ROW = (LPN_N + 1 + 63) / 64; // For K+1 bits

// --- PK Loading Logic (Host Only) ---
namespace Magic {
    constexpr uint32_t PK = 0x06660666;
    constexpr uint32_t VER = 1;
}

namespace io {
    uint32_t get32(std::istream& i) {
        uint32_t x = 0;
        i.read(reinterpret_cast<char*>(&x), 4);
        return x;
    }
    uint64_t get64(std::istream& i) {
        uint64_t x = 0;
        i.read(reinterpret_cast<char*>(&x), 8);
        return x;
    }
    // Simplified BitVec loader
    struct BitVec {
        int nbits;
        std::vector<uint64_t> w;
        static BitVec make(int n) {
            BitVec b;
            b.nbits = n;
            b.w.resize((n + 63) / 64, 0);
            return b;
        }
    };
    BitVec getBv(std::istream& i) {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < b.w.size(); ++j) b.w[j] = get64(i);
        return b;
    }
    struct Fp { uint64_t lo, hi; };
    Fp getFp(std::istream& i) {
        return { get64(i), get64(i) };
    }
}

struct PubKey {
    struct {
        uint32_t m_bits, B, lpn_t, lpn_n, lpn_tau_num, lpn_tau_den;
        uint32_t noise_entropy_bits, depth_slope_bits;
        uint64_t tuple2_fraction;
        uint32_t edge_budget;
    } prm;
    uint64_t canon_tag;
    std::vector<uint8_t> H_digest;
    std::vector<io::BitVec> H;
    struct { std::vector<uint32_t> perm, inv; } ubk;
    io::Fp omega_B;
    std::vector<io::Fp> powg_B;
};

PubKey loadPk(const std::string& path) {
    std::ifstream i(path, std::ios::binary);
    if (!i) throw std::runtime_error("cannot open " + path);
    if (io::get32(i) != Magic::PK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad pk");
    PubKey pk;
    pk.prm.m_bits = io::get32(i);
    pk.prm.B = io::get32(i);
    pk.prm.lpn_t = io::get32(i);
    pk.prm.lpn_n = io::get32(i);
    pk.prm.lpn_tau_num = io::get32(i);
    pk.prm.lpn_tau_den = io::get32(i);
    pk.prm.noise_entropy_bits = io::get32(i);
    pk.prm.depth_slope_bits = io::get32(i);
    pk.prm.tuple2_fraction = io::get64(i);
    pk.prm.edge_budget = io::get32(i);
    pk.canon_tag = io::get64(i);
    pk.H_digest.resize(32);
    i.read(reinterpret_cast<char*>(pk.H_digest.data()), 32);
    pk.H.resize(io::get64(i));
    for (auto& h : pk.H) h = io::getBv(i);
    pk.ubk.perm.resize(io::get64(i));
    for (auto& v : pk.ubk.perm) v = io::get32(i);
    pk.ubk.inv.resize(io::get64(i));
    for (auto& v : pk.ubk.inv) v = io::get32(i);
    pk.omega_B = io::getFp(i);
    pk.powg_B.resize(io::get64(i));
    for (auto& f : pk.powg_B) f = io::getFp(i);
    return pk;
}

// BitVec helpers (Host)
bool get_bit(const io::BitVec& b, size_t i) {
    if (i >= b.nbits) return false;
    return (b.w[i >> 6] >> (i & 63)) & 1;
}

// --- CUDA Kernels ---

// Kernel to perform Gaussian Elimination
// M is flattened: row-major order.
// row i is at M[i * words_per_row]
__global__ void gaussian_elim_kernel(uint64_t* M, int rows, int words_per_row, int pivot_row, int pivot_col) {
    int row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    // We only process rows > pivot_row
    // Mapping: row_idx corresponds to (pivot_row + 1 + row_idx)
    int target_row = pivot_row + 1 + row_idx;
    
    if (target_row >= rows) return;
    
    // Check if target_row has bit set at pivot_col
    // pivot_col bit is at word (pivot_col / 64), bit (pivot_col % 64)
    int word_idx = pivot_col / 64;
    int bit_idx = pivot_col % 64;
    
    uint64_t val = M[target_row * words_per_row + word_idx];
    if ((val >> bit_idx) & 1) {
        // XOR row target_row with row pivot_row
        for (int w = 0; w < words_per_row; ++w) {
            M[target_row * words_per_row + w] ^= M[pivot_row * words_per_row + w];
        }
    }
}

// Check weight of the last column (which is y)
// The last column index is rows (since matrix is rows x (rows+1))
__global__ void check_weight_kernel(uint64_t* M, int rows, int words_per_row, int* result_weight) {
    int row_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_idx >= rows) return;
    
    // Check the bit at column 'rows' (which is index K)
    // K = 4096.
    // Bit index is 4096.
    // Word index 4096 / 64 = 64. Bit 0.
    int k = rows;
    int word_idx = k / 64;
    int bit_idx = k % 64;
    
    uint64_t val = M[row_idx * words_per_row + word_idx];
    if ((val >> bit_idx) & 1) {
        atomicAdd(result_weight, 1);
    }
}

// Helper to swap rows on GPU (needed for pivoting)
// We need to find pivot first.
// Finding pivot on GPU is possible but single-threaded is easier if N is small.
// Or we can just launch a kernel to find it.
// Actually, for simplicity, let's copy the pivot column to CPU, find pivot, swap on GPU (or map index), then eliminate.
// Or implement a simple pivot search kernel.

__global__ void find_pivot_kernel(uint64_t* M, int rows, int words_per_row, int col, int start_row, int* pivot_idx) {
    // Single thread search (inefficient but safe for now)
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        int word_idx = col / 64;
        int bit_idx = col % 64;
        *pivot_idx = -1;
        for (int r = start_row; r < rows; ++r) {
            if ((M[r * words_per_row + word_idx] >> bit_idx) & 1) {
                *pivot_idx = r;
                break;
            }
        }
    }
}

__global__ void swap_rows_kernel(uint64_t* M, int words_per_row, int r1, int r2) {
    int w = threadIdx.x + blockIdx.x * blockDim.x;
    if (w < words_per_row) {
        uint64_t tmp = M[r1 * words_per_row + w];
        M[r1 * words_per_row + w] = M[r2 * words_per_row + w];
        M[r2 * words_per_row + w] = tmp;
    }
}

int main() {
    std::cout << "Starting CUDA LPN Solver...\n";
    
    // Load PK
    PubKey pk;
    io::BitVec s;
    try {
        pk = loadPk("bounty3_data/pk.bin");
        std::cout << "Loaded PK.\n";
        
        std::ifstream ict("bounty3_data/seed.ct", std::ios::binary);
        if (!ict) throw std::runtime_error("no seed.ct");
        io::get32(ict); io::get32(ict); io::get64(ict); // header
        io::get32(ict); io::get32(ict); // nL, nE
        int nL = 2;
        for (int j = 0; j < nL; ++j) {
            auto rule = (uint8_t)ict.get();
            if (rule == 0) { io::get64(ict); io::get64(ict); io::get64(ict); }
            else { io::get32(ict); io::get32(ict); }
        }
        io::get32(ict); ict.read((char*)malloc(2), 2); ict.get(); ict.get(); io::getFp(ict);
        s = io::getBv(ict);
        std::cout << "Loaded s.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    int k = pk.prm.lpn_n; // 4096
    int n = pk.H.size(); // 16384
    
    // Construct Augmented Rows on Host
    // [G | y]
    // G is K x N (stored as N columns in pk.H)
    // But we need G as K rows x N columns? 
    // Wait, solve_isd.cpp logic: G is K rows x N columns.
    // pk.H is N columns (each column is K bits).
    // We want to construct the matrix M for Gaussian Elimination.
    // M is K x K (subset of columns) + y column.
    // So M is K x (K+1).
    
    // Pre-process: Transpose pk.H to get G rows.
    // G_rows: K vectors of length N.
    std::cout << "Constructing G matrix...\n";
    std::vector<std::vector<uint64_t>> G_rows(k, std::vector<uint64_t>((n + 63) / 64, 0));
    
    for (int j = 0; j < n; ++j) {
        for (int i = 0; i < k; ++i) {
            if (get_bit(pk.H[j], i)) {
                G_rows[i][j / 64] |= (1ULL << (j % 64));
            }
        }
    }
    
    // Device Memory
    uint64_t* d_M;
    int* d_pivot_idx;
    int* d_weight;
    cudaMalloc(&d_M, k * WORDS_PER_ROW * sizeof(uint64_t));
    cudaMalloc(&d_pivot_idx, sizeof(int));
    cudaMalloc(&d_weight, sizeof(int));
    
    std::mt19937 rng(12345);
    std::vector<int> p(n);
    std::iota(p.begin(), p.end(), 0);
    
    std::vector<uint64_t> h_M(k * WORDS_PER_ROW);
    
    int max_iter = 100000;
    
    for (int iter = 0; iter < max_iter; ++iter) {
        if (iter % 10 == 0) std::cout << "Iter " << iter << "\r" << std::flush;
        
        std::shuffle(p.begin(), p.end(), rng);
        
        // Construct M (K x (K+1))
        // Column j of M corresponds to column p[j] of G.
        // Last column K is y.
        
        // Clear h_M
        std::fill(h_M.begin(), h_M.end(), 0);
        
        // Fill h_M
        // Parallelize this? O(K^2) bits ~ 16M ops. CPU is fast enough (~10ms).
        for (int i = 0; i < k; ++i) {
            for (int j = 0; j < k; ++j) {
                // Get bit at row i, col p[j]
                int original_col = p[j];
                bool bit = (G_rows[i][original_col / 64] >> (original_col % 64)) & 1;
                if (bit) {
                    h_M[i * WORDS_PER_ROW + (j / 64)] |= (1ULL << (j % 64));
                }
            }
            // Set y (last column)
            // y[i] comes from s[i]
            if (get_bit(s, i)) {
                int y_col = k;
                h_M[i * WORDS_PER_ROW + (y_col / 64)] |= (1ULL << (y_col % 64));
            }
        }
        
        // Copy to Device
        cudaMemcpy(d_M, h_M.data(), h_M.size() * sizeof(uint64_t), cudaMemcpyHostToDevice);
        
        // Gaussian Elimination on GPU
        int pivot_count = 0;
        for (int j = 0; j < k; ++j) {
            // Find pivot in column j, rows [pivot_count, k)
            find_pivot_kernel<<<1, 1>>>(d_M, k, WORDS_PER_ROW, j, pivot_count, d_pivot_idx);
            
            int pivot_idx;
            cudaMemcpy(&pivot_idx, d_pivot_idx, sizeof(int), cudaMemcpyDeviceToHost);
            
            if (pivot_idx != -1) {
                if (pivot_idx != pivot_count) {
                    swap_rows_kernel<<<1, WORDS_PER_ROW>>>(d_M, WORDS_PER_ROW, pivot_count, pivot_idx);
                }
                
                // Eliminate
                // Threads: k - pivot_count - 1
                int threads = k - pivot_count - 1;
                if (threads > 0) {
                    int blocks = (threads + 255) / 256;
                    gaussian_elim_kernel<<<blocks, 256>>>(d_M, k, WORDS_PER_ROW, pivot_count, j);
                }
                pivot_count++;
            }
        }
        
        if (pivot_count < k) continue; // Singular
        
        // Check weight
        cudaMemset(d_weight, 0, sizeof(int));
        int blocks = (k + 255) / 256;
        check_weight_kernel<<<blocks, 256>>>(d_M, k, WORDS_PER_ROW, d_weight);
        
        int w;
        cudaMemcpy(&w, d_weight, sizeof(int), cudaMemcpyDeviceToHost);
        
        if (w < 400) {
            std::cout << "\nFound candidate! Weight(y') = " << w << " at iter " << iter << "\n";
            break;
        }
    }
    
    cudaFree(d_M);
    cudaFree(d_pivot_idx);
    cudaFree(d_weight);
    
    return 0;
}
