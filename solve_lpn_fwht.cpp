#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <map>
#include <cmath>
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

// FWHT implementation
void fwht(std::vector<double>& a) {
    size_t n = a.size();
    if (n == 1) return;
    size_t half = n / 2;
    std::vector<double> left(half), right(half);
    for (size_t i = 0; i < half; ++i) {
        left[i] = a[i] + a[i + half];
        right[i] = a[i] - a[i + half];
    }
    fwht(left);
    fwht(right);
    for (size_t i = 0; i < half; ++i) {
        a[i] = left[i];
        a[i + half] = right[i];
    }
}

struct Sample {
    BitVec a; // The vector
    int b;    // The label (0 or 1)
    double noise; // Accumulated noise prob
};

int main() {
    std::cout << "Starting LPN Solver (Dimension Reduction + FWHT)...\n";

    try {
        PubKey pk = loadPk("bounty3_data/pk.bin");
        std::cout << "Loaded PK.\n";
        std::cout << "Params: n=" << pk.prm.lpn_n << ", t=" << pk.prm.lpn_t 
                  << ", m_bits=" << pk.prm.m_bits << "\n";
        
        // Load first edge from seed.ct
        std::ifstream ict("bounty3_data/seed.ct", std::ios::binary);
        if (!ict) throw std::runtime_error("no seed.ct");
        
        io::get32(ict); io::get32(ict); io::get64(ict); // header
        io::get32(ict); // nL
        auto nE = io::get32(ict); // nE
        
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
        BitVec s = io::getBv(ict); // s is y (labels)
        
        // Prepare Samples
        // Columns of pk.H are a_i. s[i] is b_i.
        // n is lpn_n (4096). We ignore the rest of m_bits (8192).
        int n = pk.prm.lpn_n; // 4096
        int t = pk.H.size();  // 16384
        
        std::cout << "Problem: Find u (" << n << " bits) from " << t << " samples.\n";
        
        std::vector<Sample> samples;
        for (int i = 0; i < t; ++i) {
            Sample samp;
            samp.a = BitVec::make(n);
            // Copy first n bits
            for (int k = 0; k < n; ++k) {
                if (get_bit(pk.H[i], k)) set_bit(samp.a, k);
            }
            samp.b = get_bit(s, i) ? 1 : 0;
            samp.noise = (double)pk.prm.lpn_tau_num / pk.prm.lpn_tau_den;
            samples.push_back(samp);
        }
        
        // LF2 Strategy: Search for sparse combinations summing to unit vectors.
        // We look for weight 3 collisions: a_i + a_j + a_k = e_m.
        // This is hard (O(t^2)).
        // We can try weight 2: a_i + a_j = e_m.
        // Or a_i = e_m (weight 1).
        
        std::cout << "Checking for weight-1 matches (a_i = e_m)...\n";
        std::vector<int> recovered_u(n, -1);
        int recovered_count = 0;
        
        for (int i = 0; i < t; ++i) {
            // Check if samples[i].a has weight 1
            int w = 0;
            int idx = -1;
            for (int k = 0; k < n; ++k) {
                if (get_bit(samples[i].a, k)) {
                    w++;
                    idx = k;
                }
            }
            if (w == 1) {
                // Found unit vector!
                // u[idx] = b_i (with prob 1-tau)
                // We can accumulate votes.
                // For now, just print.
                // std::cout << "Found unit vector for bit " << idx << " at sample " << i << "\n";
            }
        }
        
        std::cout << "Starting LF2 Search (Weight 2: a_i + a_j = e_m)...\n";
        // We can use a hash map to store a_i + e_m?
        // Too many e_m.
        // Better: Store a_i in hash map.
        // Iterate pairs? t^2/2 = 1.3e8. Feasible.
        
        // Let's try to recover bit 0.
        // We need sum = e_0 = (1, 0...0).
        // a_i + a_j = e_0 => a_i + e_0 = a_j.
        // Store a_j in hash table.
        // For each a_i, check if a_i + e_0 exists in table.
        
        std::cout << "Building hash table of samples...\n";
        // Map: first 64 bits -> list of indices
        std::map<uint64_t, std::vector<int>> table;
        for (int i = 0; i < t; ++i) {
            table[samples[i].a.w[0]].push_back(i);
        }
        
        std::cout << "Searching for weight-2 equations for first 20 bits...\n";
        int solved = 0;
        for (int target = 0; target < 20; ++target) {
            // We want a_i + a_j = e_target.
            // a_j = a_i ^ e_target.
            // We iterate all i.
            // Compute candidate = a_i ^ e_target.
            // Look up candidate in table.
            // Check full match.
            
            for (int i = 0; i < t; ++i) {
                BitVec target_vec = samples[i].a;
                // Flip bit target
                // If target < 64, we can flip w[0] and look up.
                // If target >= 64, w[0] is unchanged.
                
                uint64_t key = target_vec.w[0];
                if (target < 64) key ^= (1ULL << target);
                
                if (table.count(key)) {
                    for (int j : table[key]) {
                        if (i == j) continue;
                        // Check full equality
                        bool match = true;
                        // Start checking from w=1?
                        // Need to check bit 'target' correctly.
                        // We want a_i ^ a_j = e_target.
                        // So a_i ^ a_j should be 0 everywhere except target.
                        
                        // Check words
                        for (int w = 0; w < (n+63)/64; ++w) {
                            uint64_t diff = samples[i].a.w[w] ^ samples[j].a.w[w];
                            uint64_t expected = 0;
                            if (target >= w*64 && target < (w+1)*64) {
                                expected = (1ULL << (target % 64));
                            }
                            if (diff != expected) {
                                match = false; break;
                            }
                        }
                        
                        if (match) {
                            // Found it!
                            // u[target] = b_i ^ b_j (approx)
                            // Noise = 2*tau*(1-tau) = 0.218.
                            // Majority vote if multiple found.
                            // std::cout << "Bit " << target << ": found pair (" << i << "," << j << ")\n";
                            solved++;
                            goto next_target;
                        }
                    }
                }
            }
            next_target:;
        }
        std::cout << "Found equations for " << solved << " of first 20 bits using weight-2 collisions.\n";

        // Reduce Dimension Strategy
        // We want to solve for a small chunk of u (size L).
        // We need to eliminate n - L bits.
        // Let's target L = 20.
        int L = 20;
        int target_elim = n - L;
        
        std::cout << "Target: Eliminate " << target_elim << " bits to solve for last " << L << " bits.\n";
        
        // Since we can't eliminate all at once, we'll try to eliminate a block.
        // Block size B = 14 (log2(16384)).
        
        // 1. Permute u (by permuting bits of a)
        std::vector<int> p(n);
        std::iota(p.begin(), p.end(), 0);
        std::mt19937 rng(12345);
        std::shuffle(p.begin(), p.end(), rng);
        
        // Apply permutation to samples
        for (auto& samp : samples) {
            BitVec new_a = BitVec::make(n);
            for (int i = 0; i < n; ++i) {
                if (get_bit(samp.a, p[i])) set_bit(new_a, i);
            }
            samp.a = new_a;
        }
        
        // Now we want to zero out indices 0..target_elim-1.
        // BKW Step 1: Zero out first 14 bits.
        // Sort by first 14 bits.
        int block_bits = 14;
        
        std::sort(samples.begin(), samples.end(), [&](const Sample& a, const Sample& b) {
            // Compare first 14 bits
            for (int i = 0; i < block_bits; ++i) {
                bool bit_a = get_bit(a.a, i);
                bool bit_b = get_bit(b.a, i);
                if (bit_a != bit_b) return bit_a < bit_b;
            }
            return false;
        });
        
        std::vector<Sample> new_samples;
        int collisions = 0;
        
        for (size_t i = 0; i < samples.size() - 1; ++i) {
            // Check if match
            bool match = true;
            for (int k = 0; k < block_bits; ++k) {
                if (get_bit(samples[i].a, k) != get_bit(samples[i+1].a, k)) {
                    match = false; break;
                }
            }
            
            if (match) {
                // Create sum
                Sample combined;
                combined.a = BitVec::make(n);
                // a = a1 + a2
                for (size_t w = 0; w < (n+63)/64; ++w) {
                    combined.a.w[w] = samples[i].a.w[w] ^ samples[i+1].a.w[w];
                }
                combined.b = samples[i].b ^ samples[i+1].b;
                // Noise p' = p1(1-p2) + p2(1-p1)
                double p1 = samples[i].noise;
                double p2 = samples[i+1].noise;
                combined.noise = p1*(1-p2) + p2*(1-p1);
                
                new_samples.push_back(combined);
                collisions++;
                i++; // Skip next one to avoid reuse? Or allow reuse? 
                     // Standard BKW uses independent pairs.
            }
        }
        
        std::cout << "Step 1: Found " << collisions << " collisions on first " << block_bits << " bits.\n";
        std::cout << "New noise level: " << (new_samples.empty() ? 0 : new_samples[0].noise) << "\n";
        
        if (new_samples.empty()) {
            std::cout << "Failed to reduce dimension.\n";
            return 0;
        }
        
        // This process reduces dimension by 14 bits but increases noise.
        // With n=8192, we need ~600 steps. Noise will reach 0.5 immediately.
        
        std::cout << "Warning: BKW requires exponential samples for this dimension.\n";
        std::cout << "Attempting FWHT on a small subset of ORIGINAL variables (ignoring others as noise).\n";
        
        // "Ignore others as noise" strategy:
        // Assume u = (u_target, 0).
        // Then a . u = a_target . u_target.
        // This is only valid if u is sparse!
        // Is u sparse?
        // In G u + y = e, u is the message. It is uniform.
        // However, if we view this as Syndrome Decoding:
        // H e = s. We want sparse e.
        // Then e IS sparse.
        // We should solve for e.
        
        // Let's implement the Primal ISD check (from solve_isd.cpp) but using FWHT?
        // No, Primal ISD uses Gaussian Elimination to find low weight.
        
        std::cout << "Switching to Primal ISD logic (solving for sparse e)...\n";
        // Reload original samples?
        // We can just reuse pk.H and s.
        
        // Implement Primal ISD Loop
        int k = n; // 8192
        // We want to find e such that G u + y = e has low weight.
        // Or rather, we want to find u such that weight(G u + y) is small.
        // This minimizes the noise.
        
        // ... (Code from solve_isd.cpp) ...
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
