#include <iostream>
#include <vector>
#include <fstream>
#include <cstdint>
#include <algorithm>
#include <random>
#include <numeric>
#include <cuda_runtime.h>
#include <map>
#include <omp.h>

// --- Dual Attack / Weight-3 Search on GPU ---
// Strategy:
// 1. We want to find i, j, k such that weight(a_i ^ a_j ^ a_k) is SMALL (e.g. < 40).
// 2. This is effectively solving the problem on the Dual Code.
// 3. Algorithm:
//    - Split samples into 2 lists? No, T is small (16384).
//    - We can just iterate all pairs (i, j) on GPU, compute sum = a_i ^ a_j.
//    - Check if sum matches any a_k (or is close to any a_k)? 
//    - Actually, a simpler approach for Weight-3:
//      Compute S = { a_i | i in T }.
//      For each pair (i, j):
//         Target = a_i ^ a_j.
//         Check if Target is in S (hamming distance 0)? Or close to S?
//         Actually we want weight(a_i ^ a_j ^ a_k) to be small.
//         So we want a_i ^ a_j approx a_k.
//         This is Nearest Neighbor Search.
//
//    - GPU Approach:
//      Store all a_k in Global Memory (Texture/Constant if possible, but 16k*4k bits is 8MB, fits in L2/Global).
//      Launch kernel with 2D grid (i, j).
//      Thread (i, j) computes x = a_i ^ a_j.
//      Then we need to check if weight(x ^ a_k) is small for ANY k? That's O(T^3). Too slow (16k^3 ~ 4e12).
//      
//      Optimized Approach (Wagner's / BKW-like):
//      We only care if weight is small.
//      Most bits must be 0.
//      We can hash/bucket sort.
//
//      Let's focus on finding weight-3 CHECKS for specific bits.
//      Or just finding ANY sparse linear combination.
//      
//      Let's implement a "Batch Hamming Weight" search.
//      We iterate i.
//      We check if weight(a_i ^ a_j) is small for any j. (Weight-2 check).
//      If that fails, we try Weight-3.
//      
//      Weight-3 with GPU:
//      Precompute a table of a_k indexed by their first B bits.
//      For each pair (i, j), compute x = a_i ^ a_j.
//      Look up x in table (using first B bits).
//      If match found (candidate k), check full hamming weight of x ^ a_k.
//      
//      Parameters:
//      N = 4096.
//      T = 16384.
//      If we match on 20 bits, table size 2^20 = 1M. T is 16k.
//      So we can just use a large hash table or direct addressing array on GPU?
//      2^20 ints is 4MB. Fits easily.
//      
//      Algorithm:
//      1. Build lookup table on GPU: Table[prefix(a_k)] = k.
//         (Handle collisions? Just store one, we only need ONE good check).
//      2. Kernel:
//         For each i, j:
//            x = a_i ^ a_j.
//            p = prefix(x).
//            k = Table[p].
//            if (k != empty):
//               w = weight(x ^ a_k).
//               if (w < threshold):
//                  Report (i, j, k).

// Parameters
constexpr int LPN_N = 4096;
constexpr int LPN_T = 16384;
constexpr int WORDS = (LPN_N + 63) / 64;
constexpr int PREFIX_BITS = 18; // Increase to 18 (262k entries) for better balance
constexpr int TABLE_SIZE = (1 << PREFIX_BITS);

// Host Headers
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
    Fp getFp(std::istream& i) { return { get64(i), get64(i) }; }
}

struct PubKey {
    struct {
        uint32_t m_bits, B, lpn_t, lpn_n;
        uint32_t lpn_tau_num, lpn_tau_den;
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

bool get_bit(const io::BitVec& b, size_t i) {
    if (i >= b.nbits) return false;
    return (b.w[i >> 6] >> (i & 63)) & 1;
}

// --- GPU Kernels ---

// d_samples: T x WORDS
// d_table: TABLE_SIZE (stores index k)
__global__ void build_table_kernel(const uint64_t* d_samples, int* d_table, int t, int words) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= t) return;
    
    // Extract prefix (24 bits)
    // Assuming little endian, bits 0-23 of word 0
    uint64_t w0 = d_samples[idx * words];
    int prefix = w0 & (TABLE_SIZE - 1);
    
    // Write to table (race condition is fine, we just need ANY k)
    d_table[prefix] = idx;
}

struct Result {
    int i, j, k, w;
};

__global__ void search_kernel(const uint64_t* d_samples, const int* d_table, Result* d_res, int t, int words, int* found_count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    // idx maps to pair (i, j). 
    // i = idx / t, j = idx % t.
    // Optimization: Only i < j. 
    // Let's just do linear mapping for simplicity first.
    
    if (idx >= t * t) return;
    
    int i = idx / t;
    int j = idx % t;
    if (i >= j) return; // Avoid dupes and self
    
    // Compute x = a_i ^ a_j
    // We only need prefix first
    uint64_t w0_i = d_samples[i * words];
    uint64_t w0_j = d_samples[j * words];
    uint64_t w0_x = w0_i ^ w0_j;
    
    int prefix = w0_x & (TABLE_SIZE - 1);
    
    int k = d_table[prefix];
    
    if (k != -1 && k != i && k != j) {
        // Potential candidate!
        // Compute full weight of x ^ a_k = a_i ^ a_j ^ a_k
        int w = 0;
        for (int wd = 0; wd < words; ++wd) {
            uint64_t val = d_samples[i * words + wd] ^ d_samples[j * words + wd] ^ d_samples[k * words + wd];
            w += __popcll(val);
        }
        
    // Threshold check.
    if (w < 70) { // Relax threshold slightly from 60 to 70
        int pos = atomicAdd(found_count, 1);
        if (pos < 100) { // Store more results
            d_res[pos] = {i, j, k, w};
        }
    }
    } // End if potential candidate
} // End kernel

int main() {
    std::cout << "Starting GPU Dual Attack (Weight-3 Search)...\n";
    
    // Load Data
    PubKey pk;
    try {
        pk = loadPk("bounty3_data/pk.bin");
        std::cout << "Loaded PK. N=" << pk.prm.lpn_n << " T=" << pk.prm.lpn_t << "\n";
    } catch (std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    
    int t = pk.H.size(); // 16384
    int words = WORDS; // 64
    
    // Prepare samples buffer
    std::vector<uint64_t> h_samples(t * words);
    for (int i = 0; i < t; ++i) {
        // pk.H[i] is BitVec. Copy to buffer.
        // We need to ensure we copy LPN_N bits (4096).
        // pk.H[i] might be larger (8192).
        for (int w = 0; w < words; ++w) {
            if (w < pk.H[i].w.size()) {
                h_samples[i * words + w] = pk.H[i].w[w];
            }
        }
    }
    
    // Device Memory
    uint64_t* d_samples;
    int* d_table;
    Result* d_res;
    int* d_found;
    
    cudaMalloc(&d_samples, h_samples.size() * sizeof(uint64_t));
    cudaMalloc(&d_table, TABLE_SIZE * sizeof(int));
    cudaMalloc(&d_res, 100 * sizeof(Result));
    cudaMalloc(&d_found, sizeof(int));
    
    // Copy samples
    cudaMemcpy(d_samples, h_samples.data(), h_samples.size() * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    // Initialize Table
    cudaMemset(d_table, -1, TABLE_SIZE * sizeof(int));
    
    // 1. Build Table
    // Add Permutation loop
    // We try random permutations of columns to change the prefix.
    // If we only check the first 16 bits, we might miss collisions that happen elsewhere.
    
    std::mt19937 rng(12345);
    std::vector<int> p(LPN_N);
    std::iota(p.begin(), p.end(), 0);
    
    int max_perms = 5000; // Increase to 5000
    
    for (int iter = 0; iter < max_perms; ++iter) {
        if (iter % 100 == 0) std::cout << "Iteration " << iter << "...\n";
        std::shuffle(p.begin(), p.end(), rng);
        
        // Permute samples on host
        // Optimization: Just permute the first 16 bits? No, we need full weight check.
        // Better: Permute on GPU? Or just rebuild h_samples on host.
        // Rebuilding on host is safer for now.
        
        std::vector<uint64_t> permuted_samples(t * words, 0);
        for (int i = 0; i < t; ++i) {
            for (int bit = 0; bit < LPN_N; ++bit) {
                // Get bit p[bit] from original
                int orig_bit = p[bit];
                int orig_word = orig_bit / 64;
                int orig_offset = orig_bit % 64;
                
                if ((h_samples[i * words + orig_word] >> orig_offset) & 1) {
                    permuted_samples[i * words + (bit / 64)] |= (1ULL << (bit % 64));
                }
            }
        }
        
        cudaMemcpy(d_samples, permuted_samples.data(), permuted_samples.size() * sizeof(uint64_t), cudaMemcpyHostToDevice);
        
        // Reset
        cudaMemset(d_table, -1, TABLE_SIZE * sizeof(int));
        cudaMemset(d_found, 0, sizeof(int));
        
        int threads = 256;
        int blocks = (t + threads - 1) / threads;
        build_table_kernel<<<blocks, threads>>>(d_samples, d_table, t, words);
        cudaDeviceSynchronize();
        
        long long total_pairs = (long long)t * t;
        int grid_size = (total_pairs + threads - 1) / threads;
        search_kernel<<<grid_size, threads>>>(d_samples, d_table, d_res, t, words, d_found);
        cudaDeviceSynchronize();
        
        int found_count = 0;
        cudaMemcpy(&found_count, d_found, sizeof(int), cudaMemcpyDeviceToHost);
        
        if (found_count > 0) {
            std::cout << "FOUND " << found_count << " CANDIDATES!\n";
            // Print and break
            int count = std::min(found_count, 100);
            std::vector<Result> results(count);
            cudaMemcpy(results.data(), d_res, count * sizeof(Result), cudaMemcpyDeviceToHost);
            
            std::sort(results.begin(), results.end(), [](const Result& a, const Result& b) {
                return a.w < b.w;
            });

            for (int i = 0; i < count; ++i) {
                std::cout << "Candidate: " << results[i].i << " + " << results[i].j << " + " << results[i].k 
                          << " -> Weight " << results[i].w << "\n";
            }
            break; 
        }
    }
    
    /*
    // 1. Build Table
    int threads = 256;
    int blocks = (t + threads - 1) / threads;
    build_table_kernel<<<blocks, threads>>>(d_samples, d_table, t, words);
    cudaDeviceSynchronize();
    
    std::cout << "Table built. Starting search...\n";
    
    // 2. Search
    cudaMemset(d_found, 0, sizeof(int));
    long long total_pairs = (long long)t * t;
    int grid_size = (total_pairs + threads - 1) / threads;
    // Cap grid size if needed? 16k*16k = 256M. 1M blocks. Fine.
    
    search_kernel<<<grid_size, threads>>>(d_samples, d_table, d_res, t, words, d_found);
    cudaDeviceSynchronize();
    
    // 3. Get Results
    int found_count = 0;
    cudaMemcpy(&found_count, d_found, sizeof(int), cudaMemcpyDeviceToHost);
    
    std::cout << "Search complete. Found " << found_count << " candidates with weight < 60.\n";
    
    if (found_count > 0) {
        int count = std::min(found_count, 100);
        std::vector<Result> results(count);
        cudaMemcpy(results.data(), d_res, count * sizeof(Result), cudaMemcpyDeviceToHost);
        
        // Sort by weight
        std::sort(results.begin(), results.end(), [](const Result& a, const Result& b) {
            return a.w < b.w;
        });

        for (int i = 0; i < count; ++i) {
            std::cout << "Candidate: " << results[i].i << " + " << results[i].j << " + " << results[i].k 
                      << " -> Weight " << results[i].w << "\n";
        }
    } else {
        std::cout << "No candidates found with current prefix size (" << PREFIX_BITS << ").\n";
        std::cout << "Try reducing prefix bits or checking Weight-4.\n";
    }
    */
    
    cudaFree(d_samples);
    cudaFree(d_table);
    cudaFree(d_res);
    cudaFree(d_found);
    
    return 0;
}
