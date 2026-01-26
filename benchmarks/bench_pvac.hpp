#pragma once
#include "common.hpp"
#include <pvac/pvac.hpp>
#ifdef _OPENMP
#include <omp.h>
#endif

using namespace pvac;

inline size_t cipher_bytes(const Cipher& ct) {
    size_t sz = ct.L.size() * sizeof(Layer);
    for (const auto& e : ct.E) sz += sizeof(Edge) + e.s.w.size() * 8;
    return sz;
}

static volatile uint64_t g_sink = 0;

inline void run_pvac_scalar(std::ofstream& csv, int N = 50) {
    print_header("pvac (scalar, exact uint64, poc)");
    
    std::vector<double> kg_t;
    for (int i = 0; i < 10; i++) {
        pvac::Params p; PubKey pub; SecKey sec;
        auto t0 = Clock::now();
        keygen(p, pub, sec);
        auto t1 = Clock::now();
        kg_t.push_back(ms(t0, t1));
    }
    auto kg = calc(kg_t);
    std::cout << "keygen = " << kg.mean << " ms\n";
    csv_row(csv, "pvac", "scalar", "keygen", kg.mean, kg.stddev, "ms", 10);
    
    pvac::Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    std::cout << "security = 128-bit (lpn), lpn_n = " << prm.lpn_n << "\n";
    
    for (int i = 0; i < 5; i++) {
        auto ct = enc_value(pk, sk, 7);
        dec_value(pk, sk, ct);
        (void)ct_mul(pk, ct, ct);
        (void)ct_add(pk, ct, ct);
    }
    
    std::vector<double> enc_t, dec_t;
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto ct = enc_value(pk, sk, 12345678901ULL + i);
        auto t1 = Clock::now();
        dec_value(pk, sk, ct);
        auto t2 = Clock::now();
        enc_t.push_back(ms(t0, t1));
        dec_t.push_back(ms(t1, t2));
    }
    auto enc = calc(enc_t);
    auto dec = calc(dec_t);
    std::cout << "encrypt = " << enc.mean << " ms, decrypt = " << dec.mean << " ms\n";
    csv_row(csv, "pvac", "scalar", "encrypt", enc.mean, enc.stddev, "ms", N);
    csv_row(csv, "pvac", "scalar", "decrypt", dec.mean, dec.stddev, "ms", N);
    
    auto a = enc_value(pk, sk, 7);
    auto b = enc_value(pk, sk, 6);
    
    {
        auto m = ct_mul(pk, a, b);
        auto s = ct_add(pk, a, b);
        std::cout << "verify: 7*6 = " << dec_value(pk, sk, m).lo << ", 7+6 = " << dec_value(pk, sk, s).lo << "\n";
    }
    
    std::vector<double> mul_t, add_t;
    for (int i = 0; i < N; i++) {
        auto t0 = Clock::now();
        auto m = ct_mul(pk, a, b);
        auto t1 = Clock::now();
        auto s = ct_add(pk, a, b);
        auto t2 = Clock::now();
        g_sink += m.E.size() + s.E.size();
        mul_t.push_back(ms(t0, t1));
        add_t.push_back(ms(t1, t2));
    }
    auto mul = calc(mul_t);
    auto add = calc(add_t);
    std::cout << "mul = " << mul.mean << " ms, add = " << add.mean << " ms\n";
    csv_row(csv, "pvac", "scalar", "mul", mul.mean, mul.stddev, "ms", N);
    csv_row(csv, "pvac", "scalar", "add", add.mean, add.stddev, "ms", N);
    
    std::cout << "depth (time/ct_size): ";
    Cipher ct_d = enc_value(pk, sk, 2);
    Cipher ct_two = enc_value(pk, sk, 2);
    for (int d = 1; d <= 5; d++) {
        auto t0 = Clock::now();
        ct_d = ct_mul(pk, ct_d, ct_two);
        auto t1 = Clock::now();
        double m = ms(t0, t1);
        size_t bytes = cipher_bytes(ct_d);
        Fp v = dec_value(pk, sk, ct_d);
        std::string ok = (v.lo == (1ULL << (d + 1))) ? "ok" : "FAIL";
        std::cout << "d" << d << "=" << m << "ms/" << bytes/1024 << "KB(" << ok << ") ";
        csv_val(csv, "pvac", "scalar", "depth" + std::to_string(d), m, "ms");
        csv_val(csv, "pvac", "scalar", "depth" + std::to_string(d) + "_ct_bytes", (double)bytes, "bytes");
    }
    std::cout << "\n";
    
    std::cout << "dot: ";
    int dots[] = {4, 8, 16, 32};
    for (int n : dots) {
        std::vector<Cipher> va(n), vb(n);
        for (int i = 0; i < n; i++) {
            va[i] = enc_value(pk, sk, (uint64_t)(i + 1));
            vb[i] = enc_value(pk, sk, (uint64_t)(i + 1));
        }
        std::vector<double> dt;
        for (int r = 0; r < 5; r++) {
            auto t0 = Clock::now();
            auto acc = ct_mul(pk, va[0], vb[0]);
            for (int i = 1; i < n; i++) acc = ct_add(pk, acc, ct_mul(pk, va[i], vb[i]));
            auto t1 = Clock::now();
            dt.push_back(ms(t0, t1));
            g_sink += acc.E.size();
        }
        auto st = calc(dt);
        std::cout << "dot" << n << " = " << st.mean << "ms ";
        csv_row(csv, "pvac", "scalar", "dot" + std::to_string(n), st.mean, st.stddev, "ms", 5);
    }
    std::cout << "\n";
    
    Cipher c3 = enc_value(pk, sk, 3);
    Cipher c2 = enc_value(pk, sk, 2);
    Cipher c5 = enc_value(pk, sk, 5);
    Cipher c7 = enc_value(pk, sk, 7);
    
    std::vector<double> poly_t;
    for (int r = 0; r < 10; r++) {
        Cipher x = enc_value(pk, sk, 4);
        auto t0 = Clock::now();
        auto x2 = ct_mul(pk, x, x);
        auto x3 = ct_mul(pk, x2, x);
        auto t1c = ct_mul(pk, x3, c3);
        auto t2c = ct_mul(pk, x2, c2);
        auto t3c = ct_mul(pk, x, c5);
        auto res = ct_add(pk, t1c, ct_add(pk, t2c, ct_add(pk, t3c, c7)));
        auto t1 = Clock::now();
        poly_t.push_back(ms(t0, t1));
        g_sink += res.E.size();
    }
    auto poly = calc(poly_t);
    std::cout << "polynomial = " << poly.mean << " ms\n";
    csv_row(csv, "pvac", "scalar", "polynomial", poly.mean, poly.stddev, "ms", 10);
    
    Cipher ct_sample = enc_value(pk, sk, 123);
    size_t ct_sz = cipher_bytes(ct_sample);
    size_t pk_sz = pk.H.size() * prm.lpn_n / 8;
    std::cout << "ct_size = " << ct_sz / 1024 << " KB, pk_size = " << pk_sz / (1024 * 1024) << " MB\n";
    csv_val(csv, "pvac", "scalar", "ct_size_bytes", ct_sz, "bytes");
    csv_val(csv, "pvac", "scalar", "pk_size_bytes", pk_sz, "bytes");
}

inline void run_pvac_parallel(std::ofstream& csv) {
#ifdef _OPENMP
    print_header("pvac (parallel throughput)");
    std::cout << "threads = " << omp_get_max_threads() << "\n";
    
    pvac::Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    
    auto a = enc_value(pk, sk, 7);
    auto b = enc_value(pk, sk, 6);
    
    int ops_list[] = {512, 2048, 8192};
    for (int nops : ops_list) {
        auto t0 = Clock::now();
        for (int i = 0; i < nops; i++) {
            auto r = ct_mul(pk, a, b);
            g_sink += r.E.size();
        }
        auto t1 = Clock::now();
        double seq_ms = ms(t0, t1);
        
        auto t2 = Clock::now();
        #pragma omp parallel
        {
            uint64_t local = 0;
            #pragma omp for schedule(static)
            for (int i = 0; i < nops; i++) {
                auto r = ct_mul(pk, a, b);
                local += r.E.size();
            }
            #pragma omp atomic
            g_sink += local;
        }
        auto t3 = Clock::now();
        double par_ms = ms(t2, t3);
        
        double thr_seq = nops / (seq_ms / 1000.0);
        double thr_par = nops / (par_ms / 1000.0);
        
        std::cout << "ops = " << nops << ": seq = " << seq_ms << "ms, par = " << par_ms << "ms, ";
        std::cout << "speedup = " << seq_ms / par_ms << "x, throughput = " << thr_par << " ops/s\n";
        csv_val(csv, "pvac", "parallel", "mul_" + std::to_string(nops) + "_seq_ms", seq_ms, "ms");
        csv_val(csv, "pvac", "parallel", "mul_" + std::to_string(nops) + "_par_ms", par_ms, "ms");
        csv_val(csv, "pvac", "parallel", "mul_" + std::to_string(nops) + "_throughput", thr_par, "ops_per_sec");
    }
#endif
}