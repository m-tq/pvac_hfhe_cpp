#pragma once
#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

struct Stats {
    double mean = 0, stddev = 0, min = 0, max = 0, median = 0;
};

inline Stats calc(std::vector<double> t) {
    Stats s;
    if (t.empty()) return s;
    std::sort(t.begin(), t.end());
    s.min = t.front();
    s.max = t.back();
    s.median = (t.size() % 2) ? t[t.size()/2] : 0.5 * (t[t.size()/2 - 1] + t[t.size()/2]);
    s.mean = std::accumulate(t.begin(), t.end(), 0.0) / (double)t.size();
    double sq = 0;
    for (double x : t) sq += (x - s.mean) * (x - s.mean);
    s.stddev = std::sqrt(sq / (double)t.size());
    return s;
}

inline size_t rss_kb() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            size_t p = line.find_first_of("0123456789");
            if (p != std::string::npos) return std::stoull(line.substr(p));
        }
    }
    return 0;
}

using Clock = std::chrono::steady_clock;

inline double ms(const Clock::time_point& a, const Clock::time_point& b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

inline void csv_row(std::ofstream& csv, const std::string& scheme, const std::string& mode,
                    const std::string& op, double mean, double stddev, const std::string& unit, int n) {
    csv << scheme << "," << mode << "," << op << "," << mean << "," << stddev << "," << unit << "," << n << "\n";
}

inline void csv_val(std::ofstream& csv, const std::string& scheme, const std::string& mode,
                    const std::string& op, double val, const std::string& unit) {
    csv << scheme << "," << mode << "," << op << "," << val << ",0," << unit << ",1\n";
}

inline void print_header(const std::string& name) {
    std::cout << "\n" << name << "\n";
    std::cout << std::string(40, '_') << "\n";
}