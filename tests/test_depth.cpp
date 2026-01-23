#include <iostream>
#include <fstream>
#include <chrono>
#include <pvac/pvac.hpp>

using namespace pvac;
using Clock = std::chrono::high_resolution_clock;

static long long us_diff(const Clock::time_point& a, const Clock::time_point& b) {
    return std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
}

static void debug_sigma(const char* label, const Cipher& c) {
    std::cout << "[debug] " << label << ":\n";
    if (c.E.empty()) { std::cout << "  (no edges)\n"; return; }
    
    size_t popcnt = 0, bits = 0;
    for (const auto& e : c.E) { popcnt += e.s.popcnt(); bits += e.s.nbits; }
    
    std::cout << "edges = " << c.E.size() << " layers = " << c.L.size()
              << "popcnt = " << popcnt << " bits = " << bits
              << "ratio = " << (bits > 0 ? (double)popcnt / bits : 0) << "\n";
}

int main() {
    std::cout << "- depth stress test (ct_square + recrypt) -\n";

    Params prm; PubKey pk; SecKey sk;
    keygen(prm, pk, sk);
    EvalKey ek = make_evalkey(pk, sk, 32, 3);

    std::ofstream csv("pvac_depth.csv", std::ios::out | std::ios::trunc);
    if (!csv) { std::cerr << "cannot open depth.csv\n"; return 1; }

    csv << "mode,step,edges,layers,balance,sigma_H,sq_us,dec_us,recrypt,ok\n";

    Cipher c = enc_value(pk, sk, 2);
    Fp expected = fp_from_u64(2);

    debug_sigma("fresh enc_value(2)", c);
    std::cout << "\n[ct_square] chain c <- c^2\n";

    constexpr int max_steps = 20;
    constexpr size_t RECRYPT_THRESHOLD = 5000;
    int recrypt_count = 0;

    for (int step = 1; step <= max_steps; ++step) {
        auto t0 = Clock::now();
        c = ct_square(pk, c);
        auto t1 = Clock::now();

        expected = fp_mul(expected, expected);

        bool did_recrypt = false;
        if (c.L.size() > RECRYPT_THRESHOLD) {
            c = ct_recrypt(pk, ek, c);
            did_recrypt = true;
            recrypt_count++;
        }

        auto t2 = Clock::now();
        Fp dec = dec_value(pk, sk, c);
        auto t3 = Clock::now();

        bool ok = ct::fp_eq(dec, expected);
        double bal = sigma_density(pk, c);
        double sH = sigma_shannon(c);
        long long sq_us = us_diff(t0, t1);
        long long dec_us = us_diff(t2, t3);

        if (step == 1) debug_sigma("after first square", c);

        std::cout << "step = " << step 
                  << "edges = " << c.E.size() 
                  << "layers = " << c.L.size()
                  << "dens = " << bal 
                  << "sH = " << sH
                  << "sq_ms = " << (sq_us / 1000.0) 
                  << "dec_ms = " << (dec_us / 1000.0)
                  << (did_recrypt ? " [R]" : "")
                  << (ok ? " ok" : " FAIL") << "\n";

        csv << "square," << step << "," << c.E.size() << "," << c.L.size() << ","
            << bal << "," << sH << "," << sq_us << "," << dec_us << "," 
            << (did_recrypt ? 1 : 0) << "," << (ok ? 1 : 0) << "\n";

        csv.flush();
    }

    std::cout << "\n- final: 2^" << (1 << max_steps) << " = " << expected.lo 
              << " (recrypts = " << recrypt_count << ") -\n";

    return 0;
}