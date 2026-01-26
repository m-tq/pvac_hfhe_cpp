#pragma once
#include "common.hpp"
#include "openfhe.h"

using namespace lbcrypto;

inline void run_tfhe(std::ofstream& csv, int N = 50) {
    print_header("tfhe (bit-level, bootstrap per gate)");
    
    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128);
    
    std::cout << "security = 128-bit\n";
    
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
    csv_row(csv, "tfhe", "bit", "keygen", kg.mean, kg.stddev, "ms", 5);
    
    sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    
    for (int i = 0; i < 3; i++) {
        auto c0 = cc.Encrypt(sk, 0);
        auto c1 = cc.Encrypt(sk, 1);
        (void)cc.EvalBinGate(NAND, c0, c1);
    }
    
    std::vector<double> enc_t, dec_t;
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto ct = cc.Encrypt(sk, 1);
        auto t1 = Clock::now();
        LWEPlaintext res;
        cc.Decrypt(sk, ct, &res);
        auto t2 = Clock::now();
        enc_t.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        dec_t.push_back(std::chrono::duration<double, std::micro>(t2 - t1).count());
    }
    auto enc = calc(enc_t);
    auto dec = calc(dec_t);
    std::cout << "encrypt_1bit = " << enc.mean << " us, decrypt_1bit = " << dec.mean << " us\n";
    csv_row(csv, "tfhe", "bit", "encrypt_1bit", enc.mean, enc.stddev, "us", N);
    csv_row(csv, "tfhe", "bit", "decrypt_1bit", dec.mean, dec.stddev, "us", N);
    
    auto ct0 = cc.Encrypt(sk, 0);
    auto ct1 = cc.Encrypt(sk, 1);
    
    std::vector<double> nand_t;
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto r = cc.EvalBinGate(NAND, ct0, ct1);
        auto t1 = Clock::now();
        nand_t.push_back(ms(t0, t1));
    }
    auto nand = calc(nand_t);
    std::cout << "nand = " << nand.mean << " ms\n";
    csv_row(csv, "tfhe", "bit", "nand", nand.mean, nand.stddev, "ms", N);
    
    double mul64 = nand.mean * 24576;
    double add64 = nand.mean * 320;
    std::cout << "mul_64bit_derived = " << mul64 / 1000 / 60 << " min\n";
    std::cout << "add_64bit_derived = " << add64 / 1000 << " sec\n";
    csv_val(csv, "tfhe", "bit", "mul_64bit_derived", mul64, "ms");
    csv_val(csv, "tfhe", "bit", "add_64bit_derived", add64, "ms");
}