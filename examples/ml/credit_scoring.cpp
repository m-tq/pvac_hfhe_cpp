#include <pvac/pvac.hpp>

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace pvac;

namespace {

inline int64_t fp_to_i64_small(const Fp& a) {
    constexpr uint64_t NEG_BIT = 0x4000000000000000ULL;
    if (a.hi & NEG_BIT) {
        return -static_cast<int64_t>(fp_neg(a).lo);
    }
    return static_cast<int64_t>(a.lo);
}

struct Applicant {
    std::string name;
    uint64_t age, income_k, debt_k, savings_k;
    uint64_t history_score, employment_years, defaults, open_accounts;
};

struct Hidden2 {
    uint8_t i0;
    int64_t w0;
    uint8_t i1;
    int64_t w1;
    int64_t b;
};

struct CreditMLP {
    std::array<Hidden2, 4> hidden;
    std::array<int64_t, 4> out_w;
    int64_t out_b;

    static CreditMLP demo_model() {
        return {{
            Hidden2{0, +1, 6, +12, -60},
            Hidden2{1, -1, 2, +2,  -30},
            Hidden2{3, -1, 5, -3,  +40},
            Hidden2{4, -1, 7, +5,  -20}
        }, {+1, +1, +1, +1}, 0};
    }
};

inline std::array<int64_t, 8> to_features(const Applicant& a) {
    return {
        static_cast<int64_t>(a.age),
        static_cast<int64_t>(a.income_k),
        static_cast<int64_t>(a.debt_k),
        static_cast<int64_t>(a.savings_k),
        static_cast<int64_t>(a.history_score),
        static_cast<int64_t>(a.employment_years),
        static_cast<int64_t>(a.defaults),
        static_cast<int64_t>(a.open_accounts)
    };
}

inline int64_t cube_i128(int64_t v) {
    __int128 t = static_cast<__int128>(v) * v * v;
    return static_cast<int64_t>(t);
}

inline int64_t eval_plain(const CreditMLP& m, const Applicant& a) {
    auto x = to_features(a);
    
    auto hidden_val = [&](const Hidden2& u) -> int64_t {
        __int128 z = static_cast<__int128>(u.w0) * x[u.i0]
                   + static_cast<__int128>(u.w1) * x[u.i1]
                   + static_cast<__int128>(u.b);
        return cube_i128(static_cast<int64_t>(z));
    };
    
    __int128 out = m.out_b;
    for (size_t j = 0; j < 4; ++j) {
        out += static_cast<__int128>(m.out_w[j]) * hidden_val(m.hidden[j]);
    }
    return static_cast<int64_t>(out);
}

inline std::vector<Applicant> load_csv(const std::string& path) {
    std::vector<Applicant> out;
    std::ifstream in(path);
    if (!in) return out;

    std::string line;
    std::getline(in, line);
    
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string tok;
        Applicant a;

        std::getline(ss, a.name, ',');
        
        auto read = [&](uint64_t& v) {
            std::getline(ss, tok, ',');
            v = static_cast<uint64_t>(std::stoull(tok));
        };
        
        read(a.age); read(a.income_k); read(a.debt_k); read(a.savings_k);
        read(a.history_score); read(a.employment_years); read(a.defaults); read(a.open_accounts);
        out.push_back(a);
    }
    return out;
}

inline Cipher he_linear2(const PubKey& pk, const Cipher& x0, int64_t w0,
                         const Cipher& x1, int64_t w1, int64_t b) {
    return ct_add_const(pk, ct_add(pk, ct_mul_const(pk, x0, w0), ct_mul_const(pk, x1, w1)), b);
}

inline Cipher he_cube(const PubKey& pk, const Cipher& x) {
    return ct_mul(pk, ct_mul(pk, x, x), x);
}

inline Cipher he_infer(const PubKey& pk, const CreditMLP& model,
                       const std::array<Cipher, 8>& enc_x) {
    auto hidden_ct = [&](const Hidden2& u) {
        return he_cube(pk, he_linear2(pk, enc_x[u.i0], u.w0, enc_x[u.i1], u.w1, u.b));
    };
    
    Cipher out = ct_mul_const(pk, hidden_ct(model.hidden[0]), model.out_w[0]);
    for (size_t j = 1; j < 4; ++j) {
        out = ct_add(pk, out, ct_mul_const(pk, hidden_ct(model.hidden[j]), model.out_w[j]));
    }
    return ct_add_const(pk, out, model.out_b);
}

inline std::array<Cipher, 8> encrypt_features(const PubKey& pk, const SecKey& sk, const Applicant& a) {
    return {
        enc_value(pk, sk, a.age),
        enc_value(pk, sk, a.income_k),
        enc_value(pk, sk, a.debt_k),
        enc_value(pk, sk, a.savings_k),
        enc_value(pk, sk, a.history_score),
        enc_value(pk, sk, a.employment_years),
        enc_value(pk, sk, a.defaults),
        enc_value(pk, sk, a.open_accounts)
    };
}

inline std::vector<Applicant> default_dataset() {
    return {
        {"alice", 29, 120, 20, 35, 78, 6, 0, 4},
        {"bob",   42, 60, 110, 5, 55, 3, 2, 12},
        {"carol", 23, 45, 15, 2, 30, 1, 1, 9},
    };
}

}

int main() {
    Params prm;
    prm.m_bits = 1024;
    prm.lpn_n  = 1024;
    prm.edge_budget = 6000;

    PubKey pk;
    SecKey sk;

    std::cout << "[ml] keygen" << std::endl;
    keygen(prm, pk, sk);

    const CreditMLP model = CreditMLP::demo_model();
    auto applicants = load_csv("examples/ml/credit_db.csv");
    if (applicants.empty()) applicants = default_dataset();

    std::cout << "[ml] loaded = " << applicants.size() << " rows" << std::endl;

    for (const auto& a : applicants) {
        std::cout << "\n-- " << a.name << " --" << std::endl;

        int64_t plain = eval_plain(model, a);
        std::cout << "plain = " << plain << std::endl;

        auto enc_x = encrypt_features(pk, sk, a);
        Cipher enc_out = he_infer(pk, model, enc_x);
        int64_t he = fp_to_i64_small(dec_value(pk, sk, enc_out));

        std::cout << "he = " << he << std::endl;
        std::cout << "match = " << (he == plain ? "OK" : "MISMATCH") << std::endl;
        std::cout << "decision = " << (he > 0 ? "HIGH_RISK" : "LOW_RISK") << std::endl;
        std::cout << "ct = " << enc_out.L.size() << " layers, " << enc_out.E.size() << " edges" << std::endl;
    }

    std::cout << "\n[ml] done" << std::endl;
    return 0;
}