#pragma once
#include "common.hpp"
#include "openfhe.h"

using namespace lbcrypto;

inline void run_binfhe_ap(std::ofstream& csv, int N = 50) {
    print_header("binfhe_ap (openfhe binfhe, ap mode)");
    
    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128, AP);
    
    std::cout << "security = 128-bit, mode = ap\n";
    
    std::vector<double> kg_t;
    LWEPrivateKey sk;
    for (int i = 0; i < 5; i++) {
        auto t0 = Clock::now();
        sk = cc.KeyGen();
        cc.BTKeyGen(sk);
        auto t1 = Clock::now();
        kg_t.push_back(ms(t0, t1));
    }
    auto kg = calc(kg_t);
    std::cout << "keygen = " << kg.mean << " ms\n";
    csv_row(csv, "binfhe_ap", "bit", "keygen", kg.mean, kg.stddev, "ms", 5);
    
    sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    
    auto ct0 = cc.Encrypt(sk, 0);
    auto ct1 = cc.Encrypt(sk, 1);
    for (int i = 0; i < 3; i++) (void)cc.EvalBinGate(NAND, ct0, ct1);
    
    std::vector<double> nand_t;
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto r = cc.EvalBinGate(NAND, ct0, ct1);
        auto t1 = Clock::now();
        nand_t.push_back(ms(t0, t1));
    }
    auto nand = calc(nand_t);
    std::cout << "nand = " << nand.mean << " ms\n";
    csv_row(csv, "binfhe_ap", "bit", "nand", nand.mean, nand.stddev, "ms", N);
    
    double mul64 = nand.mean * 24576;
    std::cout << "mul_64bit_derived = " << mul64 / 1000 / 60 << " min\n";
    csv_val(csv, "binfhe_ap", "bit", "mul_64bit_derived", mul64, "ms");
}
