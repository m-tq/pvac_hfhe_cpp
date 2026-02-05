#include <pvac/pvac.hpp>
#include <iostream>
#include <fstream>
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

int main() {
    std::cout << "Start check_params" << std::endl;
    std::ifstream i("bounty3_data/pk.bin", std::ios::binary);
    if (!i) { std::cerr << "Error opening pk.bin\n"; return 1; }
    
    if (io::get32(i) != Magic::PK || io::get32(i) != Magic::VER) {
        std::cerr << "Bad magic\n"; return 1;
    }

    std::cout << "m_bits: " << io::get32(i) << "\n";
    std::cout << "B: " << io::get32(i) << "\n";
    std::cout << "lpn_t: " << io::get32(i) << "\n";
    std::cout << "lpn_n: " << io::get32(i) << "\n";
    std::cout << "lpn_tau_num: " << io::get32(i) << "\n";
    std::cout << "lpn_tau_den: " << io::get32(i) << "\n";
    std::cout << "noise_entropy_bits: " << io::get32(i) << "\n";
    std::cout << "depth_slope_bits: " << io::get32(i) << "\n";
    
    return 0;
}
