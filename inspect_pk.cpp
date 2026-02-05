
#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>

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

int main() {
    std::cout << "Starting inspect_pk...\n";
    // Helper for BitVec access
    auto get_bit = [](const BitVec& b, size_t i) -> bool {
        if (i >= b.nbits) return false;
        return (b.w[i >> 6] >> (i & 63)) & 1;
    };
    
    auto set_bit = [](BitVec& b, size_t i) {
        if (i < b.nbits) {
            b.w[i >> 6] |= (1ULL << (i & 63));
        }
    };

    try {
        PubKey pk = loadPk("bounty3_data/pk.bin");
        std::cout << "m_bits: " << pk.prm.m_bits << "\n";
        std::cout << "lpn_n: " << pk.prm.lpn_n << "\n";
        std::cout << "lpn_t: " << pk.prm.lpn_t << "\n";
        std::cout << "H size: " << pk.H.size() << "\n";
        if (!pk.H.empty()) {
            std::cout << "H[0] bits: " << pk.H[0].nbits << "\n";
        }
        
        // Load seed.ct
        std::ifstream ict("bounty3_data/seed.ct", std::ios::binary);
        if (ict) {
            auto magic = io::get32(ict);
            auto ver = io::get32(ict);
            auto nC = io::get64(ict);
            std::cout << "seed.ct: " << nC << " ciphers\n";
            for (size_t i = 0; i < nC; ++i) {
                // ser::getCipher
                auto nL = io::get32(ict);
                auto nE = io::get32(ict);
                std::cout << "Cipher " << i << ": L=" << nL << " E=" << nE << "\n";
                // skip L
                for (size_t j = 0; j < nL; ++j) {
                     // getLayer
                     auto rule = (uint8_t)ict.get();
                     if (rule == 0) { // BASE
                         io::get64(ict); io::get64(ict); io::get64(ict);
                     } else { // PROD
                         io::get32(ict); io::get32(ict);
                     }
                }
                // skip E
                for (size_t j = 0; j < nE; ++j) {
                    // getEdge
                    io::get32(ict); // layer_id
                    ict.read((char*)malloc(2), 2); // idx
                    ict.get(); // ch
                    ict.get(); // pad
                    io::getFp(ict); // w
                    // s
                    auto nbits = io::get32(ict);
                    size_t nwords = (nbits + 63) / 64;
                    for (size_t k = 0; k < nwords; ++k) io::get64(ict);
                }
            }
        }
        
        
        // Compute rank of H
        // H is vector of BitVec (columns).
        // Convert to rows first for Gaussian elimination?
        // Or do column reduction? Rank is same.
        // H has 16384 columns, 8192 rows.
        // Let's form the matrix 8192 x 16384.
        
        size_t rows = pk.prm.m_bits;
        size_t cols = pk.H.size();
        
        std::cout << "Computing rank of " << rows << " x " << cols << " matrix...\n";
        
        // Store as rows for standard Gaussian elimination
        // BitVec uses array of uint64_t.
        // We can use std::vector<BitVec> where each BitVec is a row.
        // But pk.H is columns. We need to transpose.
        
        // Transpose H to get rows
        std::vector<BitVec> matrix_rows(rows);
        for (size_t i = 0; i < rows; ++i) {
            matrix_rows[i] = BitVec::make(cols);
        }
        
        for (size_t j = 0; j < cols; ++j) {
            const auto& col = pk.H[j];
            for (size_t i = 0; i < rows; ++i) {
                if (get_bit(col, i)) {
                    set_bit(matrix_rows[i], j);
                }
            }
        }
        
        // Gaussian elimination
        size_t pivot_row = 0;
        std::vector<size_t> pivot_cols;
        
        for (size_t j = 0; j < cols && pivot_row < rows; ++j) {
            // Find pivot in column j, starting from pivot_row
            size_t sel = rows;
            for (size_t i = pivot_row; i < rows; ++i) {
                if (get_bit(matrix_rows[i], j)) {
                    sel = i;
                    break;
                }
            }
            
            if (sel < rows) {
                // Swap rows
                if (sel != pivot_row) {
                    std::swap(matrix_rows[pivot_row], matrix_rows[sel]);
                }
                
                // Eliminate other rows
                for (size_t i = 0; i < rows; ++i) {
                    if (i != pivot_row && get_bit(matrix_rows[i], j)) {
                        matrix_rows[i].xor_with(matrix_rows[pivot_row]);
                    }
                }
                
                pivot_cols.push_back(j);
                pivot_row++;
            }
        }
        
        std::cout << "Rank: " << pivot_row << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
