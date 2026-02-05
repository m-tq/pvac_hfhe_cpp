
#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>

using namespace pvac;

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
    BitVec getBv(std::istream& i) {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    }
    Fp getFp(std::istream& i) {
        return { get64(i), get64(i) };
    }
}

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

// BitVec helpers
bool get_bit(const BitVec& b, size_t i) {
    if (i >= b.nbits) return false;
    return (b.w[i >> 6] >> (i & 63)) & 1;
}

void set_bit(BitVec& b, size_t i) {
    if (i < b.nbits) {
        b.w[i >> 6] |= (1ULL << (i & 63));
    }
}

int main() {
    std::cout << "Starting solve_isd (G u + y = e)...\n";
    try {
        PubKey pk = loadPk("bounty3_data/pk.bin");
        std::cout << "Loaded PK.\n";
        
        // Load first edge from seed.ct
        std::ifstream ict("bounty3_data/seed.ct", std::ios::binary);
        if (!ict) throw std::runtime_error("no seed.ct");
        
        io::get32(ict); io::get32(ict); io::get64(ict); // header
        io::get32(ict); // nL
        auto nE = io::get32(ict); // nE
        std::cout << "Cipher 0 has " << nE << " edges.\n";
        
        // Skip layers
        int nL = 2; 
        for (int j = 0; j < nL; ++j) {
            auto rule = (uint8_t)ict.get();
            if (rule == 0) { io::get64(ict); io::get64(ict); io::get64(ict); }
            else { io::get32(ict); io::get32(ict); }
        }
        
        // Read first edge
        io::get32(ict); // layer_id
        ict.read((char*)malloc(2), 2); // idx
        ict.get(); // ch
        ict.get(); // pad
        io::getFp(ict); // w
        BitVec s = io::getBv(ict); // s is y
        
        std::cout << "Loaded edge s (" << s.nbits << " bits).\n";
        
        // Problem: G u + y = e
        // G = pk.H (columns). Size 8192 x 16384.
        // y = s. Size 8192.
        // We want u (weight ~128) and e (weight ~128).
        
        int n = pk.H.size(); // 16384
        int k = pk.prm.lpn_n; // 4096 (was m_bits=8192)
        
        std::cout << "G: " << k << " x " << n << "\n";
        
        // Construct G rows (BitVecs of length n)
        // We only use the first k columns of G (which are rows of pk.H?)
        // pk.H is vector of BitVecs.
        // We assumed pk.H columns are samples.
        // In solve_isd.cpp logic:
        // for (int j = 0; j < n; ++j) {
        //    const auto& col = pk.H[j];
        //    for (int i = 0; i < k; ++i) if (get_bit(col, i)) set_bit(G_rows[i], j);
        // }
        // This assumes pk.H[j] has length >= k.
        // If m_bits=8192, and we only use k=4096, we just ignore the rest.
        // This is correct if u is zero on the rest.
        
        std::vector<BitVec> G_rows(k);
        for (int i = 0; i < k; ++i) G_rows[i] = BitVec::make(n);
        
        for (int j = 0; j < n; ++j) {
            const auto& col = pk.H[j];
            for (int i = 0; i < k; ++i) {
                if (get_bit(col, i)) set_bit(G_rows[i], j);
            }
        }
        
        // Store y as BitVec of length k? No, y is column vector of length k.
        // We augment G with y.
        // But y is affected by row operations.
        // So we should store y as a BitVec of length k, but we need to apply ops.
        // Better: Store [G | y]. y is the (n)-th column.
        // We can store G rows as BitVec of length n+1.
        
        std::vector<BitVec> Aug_rows(k);
        for (int i = 0; i < k; ++i) {
            Aug_rows[i] = BitVec::make(n + 1);
            // Copy G_rows[i]
            for (size_t w = 0; w < (n + 63) / 64; ++w) {
                 Aug_rows[i].w[w] = G_rows[i].w[w];
            }
            // Set y bit
            if (get_bit(s, i)) set_bit(Aug_rows[i], n);
        }
        
        std::mt19937 rng(12345);
        std::vector<int> p(n);
        std::iota(p.begin(), p.end(), 0);
        
        int max_iter = 100000;
        
        for (int iter = 0; iter < max_iter; ++iter) {
            std::shuffle(p.begin(), p.end(), rng);
            
            // We need to pivot on the first k columns of permuted G.
            // We construct the matrix for elimination.
            // M has k rows. We need to track y.
            
            std::vector<BitVec> M(k);
            for (int i = 0; i < k; ++i) M[i] = BitVec::make(k + 1); // Only store relevant cols + y
            
            // Map permuted indices to 0..k-1
            // We only care about the first k columns for pivoting.
            // And the y column.
            
            for (int i = 0; i < k; ++i) {
                for (int j = 0; j < k; ++j) {
                    if (get_bit(Aug_rows[i], p[j])) set_bit(M[i], j);
                }
                if (get_bit(Aug_rows[i], n)) set_bit(M[i], k); // y
            }
            
            // Gaussian Elimination
            std::vector<int> pivot_row(k, -1);
            int pivot_count = 0;
            
            for (int j = 0; j < k; ++j) {
                int sel = -1;
                for (int i = pivot_count; i < k; ++i) {
                    if (get_bit(M[i], j)) {
                        sel = i;
                        break;
                    }
                }
                
                if (sel != -1) {
                    if (sel != pivot_count) std::swap(M[pivot_count], M[sel]);
                    
                    for (int i = 0; i < k; ++i) {
                        if (i != pivot_count && get_bit(M[i], j)) {
                            M[i].xor_with(M[pivot_count]);
                        }
                    }
                    pivot_count++;
                }
            }
            
            if (pivot_count < k) {
                // Singular
                continue;
            }
            
            // Now M is [I | y'].
            // y' is the last column.
            // y' = u_1 + e (assuming u_2 = 0).
            // Check weight of y'.
            int w = 0;
            for (int i = 0; i < k; ++i) {
                if (get_bit(M[i], k)) w++;
            }
            
            if (w < 400) {
                std::cout << "Found candidate! Weight(y') = " << w << " at iter " << iter << "\n";
                // Print indices where y' is 1
                // These correspond to u_1 indices (permuted).
                // u_1[i] = 1 => u[p[i]] = 1.
                // e also contributes.
                // We can assume e is small or zero?
                // Actually y' = u_1 + e.
                // If w is small, it means u_1 + e is sparse.
                // Since u_1 and e are both sparse (weight ~128), sum is weight ~256.
                // If we find w < 400, it's consistent.
                // We can output the vector and verify.
                return 0;
            }
            
            if (iter % 100 == 0) std::cout << "Iter " << iter << "\r" << std::flush;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
