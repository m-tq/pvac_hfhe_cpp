#pragma once
#include "common.hpp"
#include "openfhe.h"

using namespace lbcrypto;

inline void run_ckks_scalar(std::ofstream& csv, int N = 50) {
    print_header("ckks (scalar, approximate)");
    
    CCParams<CryptoContextCKKSRNS> p;
    p.SetMultiplicativeDepth(5);
    p.SetScalingModSize(50);
    p.SetBatchSize(1);
    p.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(p);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    
    std::cout << "security = 128-bit, type = approximate\n";
    
    std::vector<double> kg_t;
    KeyPair<DCRTPoly> kp;
    for (int i = 0; i < 10; i++) {
        auto t0 = Clock::now();
        kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
        auto t1 = Clock::now();
        kg_t.push_back(ms(t0, t1));
    }
    auto kg = calc(kg_t);
    std::cout << "keygen = " << kg.mean << " ms\n";
    csv_row(csv, "ckks", "scalar", "keygen", kg.mean, kg.stddev, "ms", 10);
    
    kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    
    auto pt7 = cc->MakeCKKSPackedPlaintext(std::vector<double>{7.0});
    auto pt6 = cc->MakeCKKSPackedPlaintext(std::vector<double>{6.0});
    
    for (int i = 0; i < 5; i++) {
        auto ct = cc->Encrypt(kp.publicKey, pt7);
        Plaintext res;
        cc->Decrypt(kp.secretKey, ct, &res);
        (void)cc->EvalMult(ct, ct);
        (void)cc->EvalAdd(ct, ct);
    }
    
    std::vector<double> enc_t, dec_t, mul_t, add_t;
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto ct = cc->Encrypt(kp.publicKey, pt7);
        auto t1 = Clock::now();
        Plaintext res;
        cc->Decrypt(kp.secretKey, ct, &res);
        auto t2 = Clock::now();
        enc_t.push_back(ms(t0, t1));
        dec_t.push_back(ms(t1, t2));
    }
    auto enc = calc(enc_t);
    auto dec = calc(dec_t);
    std::cout << "encrypt = " << enc.mean << " ms, decrypt = " << dec.mean << " ms\n";
    csv_row(csv, "ckks", "scalar", "encrypt", enc.mean, enc.stddev, "ms", N);
    csv_row(csv, "ckks", "scalar", "decrypt", dec.mean, dec.stddev, "ms", N);
    
    auto ct_a = cc->Encrypt(kp.publicKey, pt7);
    auto ct_b = cc->Encrypt(kp.publicKey, pt6);
    
    {
        auto m = cc->EvalMult(ct_a, ct_b);
        auto s = cc->EvalAdd(ct_a, ct_b);
        Plaintext pm, ps;
        cc->Decrypt(kp.secretKey, m, &pm);
        cc->Decrypt(kp.secretKey, s, &ps);
        auto vm = pm->GetRealPackedValue()[0];
        auto vs = ps->GetRealPackedValue()[0];
        double err_m = std::fabs(vm - 42.0);
        double err_s = std::fabs(vs - 13.0);
        std::cout << "verify: 7*6 = " << vm << " (err=" << err_m << "), 7+6 = " << vs << " (err=" << err_s << ")";
        std::cout << ((err_m < 0.01 && err_s < 0.01) ? " (ok)" : " (FAIL)") << "\n";
    }
    
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto r = cc->EvalMult(ct_a, ct_b);
        auto t1 = Clock::now();
        auto s = cc->EvalAdd(ct_a, ct_b);
        auto t2 = Clock::now();
        mul_t.push_back(ms(t0, t1));
        add_t.push_back(ms(t1, t2));
    }
    auto mul = calc(mul_t);
    auto add = calc(add_t);
    std::cout << "mul = " << mul.mean << " ms, add = " << add.mean << " ms\n";
    csv_row(csv, "ckks", "scalar", "mul", mul.mean, mul.stddev, "ms", N);
    csv_row(csv, "ckks", "scalar", "add", add.mean, add.stddev, "ms", N);
    
    std::cout << "depth: ";
    auto ct_d = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{2.0}));
    for (int d = 1; d <= 5; d++) {
        auto t0 = Clock::now();
        ct_d = cc->EvalMult(ct_d, ct_b);
        auto t1 = Clock::now();
        double m = ms(t0, t1);
        std::cout << "d" << d << " = " << m << "ms ";
        csv_val(csv, "ckks", "scalar", "depth" + std::to_string(d), m, "ms");
    }
    std::cout << "\n";
    
    std::cout << "dot: ";
    int dots[] = {4, 8, 16, 32};
    for (int n : dots) {
        std::vector<Ciphertext<DCRTPoly>> va(n), vb(n);
        for (int i = 0; i < n; i++) {
            va[i] = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{(double)(i + 1)}));
            vb[i] = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{(double)(i + 1)}));
        }
        std::vector<double> dt;
        for (int r = 0; r < 5; r++) {
            auto t0 = Clock::now();
            auto acc = cc->EvalMult(va[0], vb[0]);
            for (int i = 1; i < n; i++) acc = cc->EvalAdd(acc, cc->EvalMult(va[i], vb[i]));
            auto t1 = Clock::now();
            dt.push_back(ms(t0, t1));
        }
        auto st = calc(dt);
        std::cout << "dot" << n << " = " << st.mean << "ms ";
        csv_row(csv, "ckks", "scalar", "dot" + std::to_string(n), st.mean, st.stddev, "ms", 5);
    }
    std::cout << "\n";
    
    auto ct_x = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{4.0}));
    auto ct_3 = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{3.0}));
    auto ct_2 = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{2.0}));
    auto ct_5 = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{5.0}));
    auto ct_7 = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{7.0}));
    
    std::vector<double> poly_t;
    for (int i = 0; i < 10; i++) {
        auto t0 = Clock::now();
        auto x2 = cc->EvalMult(ct_x, ct_x);
        auto x3 = cc->EvalMult(x2, ct_x);
        auto t1c = cc->EvalMult(x3, ct_3);
        auto t2c = cc->EvalMult(x2, ct_2);
        auto t3c = cc->EvalMult(ct_x, ct_5);
        auto res = cc->EvalAdd(t1c, cc->EvalAdd(t2c, cc->EvalAdd(t3c, ct_7)));
        auto t1 = Clock::now();
        poly_t.push_back(ms(t0, t1));
    }
    auto poly = calc(poly_t);
    std::cout << "polynomial = " << poly.mean << " ms\n";
    csv_row(csv, "ckks", "scalar", "polynomial", poly.mean, poly.stddev, "ms", 10);
    
    const auto& elems = ct_a->GetElements();
    size_t polys = elems.size();
    size_t towers = elems[0].GetNumOfElements();
    size_t ring = elems[0].GetRingDimension();
    size_t ct_est = polys * towers * ring * sizeof(uint64_t);
    std::cout << "ct_size_est = " << ct_est / 1024 << " KB (polys = " << polys << ", towers = " << towers << ", ring = " << ring << ")\n";
    csv_val(csv, "ckks", "scalar", "ct_size_est_bytes", ct_est, "bytes");
}

inline void run_ckks_simd(std::ofstream& csv, int N = 50) {
    print_header("ckks (simd)");
    
    uint32_t batchSize = 4096;
    CCParams<CryptoContextCKKSRNS> p;
    p.SetMultiplicativeDepth(5);
    p.SetScalingModSize(50);
    p.SetBatchSize(batchSize);
    p.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(p);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    
    std::cout << "slots = " << batchSize << "\n";
    
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    
    std::vector<int> rots;
    for (uint32_t i = 1; i < batchSize; i *= 2) rots.push_back(i);
    
    auto t_rk0 = Clock::now();
    cc->EvalRotateKeyGen(kp.secretKey, rots);
    auto t_rk1 = Clock::now();
    double rk_ms = ms(t_rk0, t_rk1);
    std::cout << "rotate_keygen = " << rk_ms << " ms\n";
    csv_val(csv, "ckks", "simd", "rotate_keygen", rk_ms, "ms");
    
    std::vector<double> va(batchSize), vb(batchSize);
    for (uint32_t i = 0; i < batchSize; i++) { va[i] = i % 100 + 1.0; vb[i] = i % 100 + 1.0; }
    
    auto ct_a = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(va));
    auto ct_b = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(vb));
    
    for (int i = 0; i < 3; i++) {
        auto prod = cc->EvalMult(ct_a, ct_b);
        for (uint32_t r = 1; r < batchSize; r *= 2) prod = cc->EvalAdd(prod, cc->EvalRotate(prod, r));
    }
    
    std::vector<double> mul_t;
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto r = cc->EvalMult(ct_a, ct_b);
        auto t1 = Clock::now();
        mul_t.push_back(ms(t0, t1));
    }
    auto mul = calc(mul_t);
    std::cout << "mul = " << mul.mean << " ms (" << mul.mean / batchSize * 1000 << " us/slot)\n";
    csv_row(csv, "ckks", "simd", "mul", mul.mean, mul.stddev, "ms", N);
    csv_val(csv, "ckks", "simd", "mul_per_slot_us", mul.mean / batchSize * 1000, "us");
    
    std::vector<double> dot_t;
    for (int i = 0; i < 10; i++) {
        auto t0 = Clock::now();
        auto prod = cc->EvalMult(ct_a, ct_b);
        for (uint32_t r = 1; r < batchSize; r *= 2) prod = cc->EvalAdd(prod, cc->EvalRotate(prod, r));
        auto t1 = Clock::now();
        dot_t.push_back(ms(t0, t1));
    }
    auto dot = calc(dot_t);
    std::cout << "dot" << batchSize << " = " << dot.mean << " ms\n";
    csv_row(csv, "ckks", "simd", "dot" + std::to_string(batchSize), dot.mean, dot.stddev, "ms", 10);
}