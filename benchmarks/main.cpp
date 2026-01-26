#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <cstring>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "common.hpp"
#include "bench_bfv.hpp"
#include "bench_bgv.hpp"
#include "bench_ckks.hpp"
#include "bench_tfhe.hpp"
#include "bench_binfhe.hpp"
#include "bench_fhew.hpp"
#include "bench_pvac.hpp"

void print_usage() {
    std::cout << "usage:\n";
    std::cout << "./bench -all -- run all, save to results/all.csv\n";
    std::cout << "./bench -compare binfhe pvac -- compare schemes\n";
    std::cout << "./bench -scheme bfv -- run single scheme\n";
    std::cout << "schemes: bfv, bgv, ckks, tfhe, fhew, binfhe, pvac-hfhe (PoC and early version without optimizations)\n";
}

int main(int argc, char** argv) {
    std::cout << std::fixed << std::setprecision(2);
    
    if (argc < 2) {
        print_usage();
        return 1;
    }
    
    std::set<std::string> targets;
    std::string csv_name = "results/bench.csv";
    
    if (std::strcmp(argv[1], "-all") == 0) {
        targets = {"bfv", "bgv", "ckks", "tfhe", "fhew", "binfhe", "pvac"};
        csv_name = "results/all.csv";
    }
    else if (std::strcmp(argv[1], "-compare") == 0 && argc >= 4) {
        for (int i = 2; i < argc; i++) targets.insert(argv[i]);
        csv_name = "results/";
        for (int i = 2; i < argc; i++) {
            csv_name += argv[i];
            if (i < argc - 1) csv_name += "_";
        }
        csv_name += ".csv";
    }
    else if (std::strcmp(argv[1], "-scheme") == 0 && argc >= 3) {
        targets.insert(argv[2]);
        csv_name = std::string("results/") + argv[2] + ".csv";
    }
    else {
        print_usage();
        return 1;
    }
    
    std::ofstream csv(csv_name);
    csv << "scheme,mode,op,mean,stddev,unit,n\n";
    
    std::cout << "fhe benchmarks\n";
    std::cout << std::string(40, '_') << "\n";
    std::cout << "targets: ";
    for (const auto& t : targets) std::cout << t << " ";
    std::cout << "\noutput: " << csv_name << "\n";
    
#ifdef _OPENMP
    std::cout << "omp_threads = " << omp_get_max_threads() << "\n";
#else
    std::cout << "omp_threads = 1 (openmp disabled)\n";
#endif
    
    if (targets.count("bfv")) {
        run_bfv_scalar(csv);
        run_bfv_simd(csv);
        run_bfv_multimod(csv);
        run_bfv_shallow(csv);
    }
    if (targets.count("bgv")) {
        run_bgv_scalar(csv);
    }
    if (targets.count("ckks")) {
        run_ckks_scalar(csv);
        run_ckks_simd(csv);
    }
    if (targets.count("tfhe")) {
        run_tfhe(csv);
    }
    if (targets.count("fhew")) {
        run_fhew(csv);
    }
    if (targets.count("binfhe")) {
        run_binfhe_ap(csv);
    }
    if (targets.count("pvac")) {
        run_pvac_scalar(csv);
        run_pvac_parallel(csv);
    }
    
    csv.close();
    
    std::cout << "\n" << std::string(40, '_') << "\n";
    std::cout << "done. saved to " << csv_name << "\n";
    
    return 0;
}