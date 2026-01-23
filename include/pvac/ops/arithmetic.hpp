#pragma once

#include <cstdint>
#include <vector>
#include <algorithm>
#include <functional>
#include <numeric>
#include <utility>

#include "../core/types.hpp"
#include "encrypt.hpp"

namespace pvac {

namespace detail {

template<typename F>
inline auto fold_edges(const Cipher& ct, const PubKey& pk, F&& acc_fn) {
    std::vector<Fp> out(ct.L.size(), Fp{0, 0});
    for (const auto& e : ct.E) {
        out[e.layer_id] = acc_fn(out[e.layer_id], fp_mul(e.w, pk.powg_B[e.idx]), e.ch);
    }
    return out;
}

inline auto gsum_accumulator = [](const Fp& acc, const Fp& term, uint8_t ch) -> Fp {
    return ch == SGN_P ? fp_add(acc, term) : fp_sub(acc, term);
};

inline void sample_unique_indices(uint16_t* dst, size_t n, int B) {
    for (size_t i = 0; i < n; ++i) {
        uint16_t x;
        do {
            x = static_cast<uint16_t>(csprng_u64() % static_cast<uint64_t>(B));
        } while (std::any_of(dst, dst + i, [x](uint16_t v) { return v == x; }));
        dst[i] = x;
    }
}

inline Edge make_repack_edge(const PubKey& pk, const Layer& L, uint32_t lid, 
                             uint16_t idx, uint8_t ch, const Fp& w) {
    return {lid, idx, ch, w, sigma_from_H(pk, L.seed.ztag, L.seed.nonce, idx, ch, csprng_u64())};
}

inline auto emit_repack_edges(const PubKey& pk, uint32_t lid, const Layer& L, 
                              const Fp& target, size_t s) -> std::vector<Edge> {
    if (s == 0) return {};
    
    std::vector<uint16_t> idxs(s);
    sample_unique_indices(idxs.data(), s, pk.prm.B);
    
    std::vector<std::pair<uint16_t, uint8_t>> specs(s);
    std::transform(idxs.begin(), idxs.end(), specs.begin(), [](uint16_t idx) {
        return std::make_pair(idx, static_cast<uint8_t>(csprng_u64() & 1));
    });
    
    Fp sum{0, 0};
    std::vector<Edge> edges;
    edges.reserve(s);
    
    for (size_t i = 0; i + 1 < s; ++i) {
        auto [idx, ch] = specs[i];
        Fp w = rand_fp_nonzero();
        Fp t = fp_mul(w, pk.powg_B[idx]);
        sum = ch == SGN_P ? fp_add(sum, t) : fp_sub(sum, t);
        edges.push_back(make_repack_edge(pk, L, lid, idx, ch, w));
    }
    
    auto [last_idx, last_ch] = specs.back();
    Fp diff = fp_sub(target, sum);
    Fp final_w = fp_mul(last_ch == SGN_M ? fp_neg(diff) : diff,
                        pk.powg_B[(pk.prm.B - last_idx) % pk.prm.B]);
    
    edges.push_back(make_repack_edge(pk, L, lid, last_idx, last_ch, final_w));
    return edges;
}

inline Layer make_prod_layer(const PubKey& pk, uint32_t pa, uint32_t pb) {
    auto nonce = make_nonce128();
    return {RRule::PROD, {prg_layer_ztag(pk.canon_tag, nonce), nonce}, 
            pa < pb ? pa : pb, pa < pb ? pb : pa};
}

template<typename LayerGen, typename TargetGen>
inline Cipher build_product_cipher(const PubKey& pk, const Cipher& A, const Cipher* B,
                                   LayerGen&& layer_gen, TargetGen&& target_gen, 
                                   size_t num_prods, size_t S, const char* tag) {
    Cipher C;
    auto gA = fold_edges(A, pk, gsum_accumulator);
    auto gB = B ? fold_edges(*B, pk, gsum_accumulator) : gA;
    
    C.L = A.L;
    uint32_t off = static_cast<uint32_t>(C.L.size());
    
    if (B) {
        C.L.reserve(C.L.size() + B->L.size() + num_prods);
        std::transform(B->L.begin(), B->L.end(), std::back_inserter(C.L),
            [off](Layer L) {
                if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
                return L;
            });
    } else {
        C.L.reserve(C.L.size() + num_prods);
    }
    
    C.E.reserve(num_prods * S);
    
    layer_gen([&](uint32_t la, uint32_t lb_raw) {
        uint32_t lb = B ? (off + lb_raw) : lb_raw;
        Layer L = make_prod_layer(pk, la, lb);
        uint32_t lid = static_cast<uint32_t>(C.L.size());
        C.L.push_back(L);
        
        Fp target = target_gen(gA, gB, la, lb_raw);
        auto edges = emit_repack_edges(pk, lid, C.L[lid], target, S);
        std::move(edges.begin(), edges.end(), std::back_inserter(C.E));
    });
    
    guard_budget(pk, C, tag);
    compact_layers(C);
    return C;
}

} // namespace detail

inline Cipher ct_scale(const PubKey&, const Cipher& A, const Fp& s) {
    Cipher C = A;
    std::for_each(C.E.begin(), C.E.end(), [&s](Edge& e) { e.w = fp_mul(e.w, s); });
    return C;
}

inline Cipher ct_neg(const PubKey& pk, const Cipher& A) {
    return ct_scale(pk, A, fp_neg(fp_from_u64(1)));
}

inline Cipher ct_add(const PubKey& pk, const Cipher& A, const Cipher& B) {
    Cipher C;
    C.L.reserve(A.L.size() + B.L.size());
    C.E.reserve(A.E.size() + B.E.size());
    
    C.L = A.L;
    uint32_t off = static_cast<uint32_t>(A.L.size());
    
    std::transform(B.L.begin(), B.L.end(), std::back_inserter(C.L),
        [off](Layer L) {
            if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
            return L;
        });
    
    C.E = A.E;
    std::transform(B.E.begin(), B.E.end(), std::back_inserter(C.E),
        [off](Edge e) { e.layer_id += off; return e; });
    
    guard_budget(pk, C, "add");
    compact_layers(C);
    return C;
}

inline Cipher ct_sub(const PubKey& pk, const Cipher& A, const Cipher& B) {
    return ct_add(pk, A, ct_neg(pk, B));
}

inline Cipher ct_mul(const PubKey& pk, const Cipher& A, const Cipher& B, size_t S = 8) {
    uint32_t LA = static_cast<uint32_t>(A.L.size());
    uint32_t LB = static_cast<uint32_t>(B.L.size());
    
    return detail::build_product_cipher(pk, A, &B,
        [LA, LB](auto&& emit) {
            for (uint32_t la = 0; la < LA; ++la)
                for (uint32_t lb = 0; lb < LB; ++lb)
                    emit(la, lb);
        },
        [](const auto& gA, const auto& gB, uint32_t la, uint32_t lb) {
            return fp_mul(gA[la], gB[lb]);
        },
        static_cast<size_t>(LA) * LB, S ? S : 1, "mul");
}

inline Cipher ct_square(const PubKey& pk, const Cipher& A, size_t S = 8) {
    uint32_t LA = static_cast<uint32_t>(A.L.size());
    size_t triangular = static_cast<size_t>(LA) * (LA + 1) / 2;
    
    return detail::build_product_cipher(pk, A, nullptr,
        [LA](auto&& emit) {
            for (uint32_t la = 0; la < LA; ++la)
                for (uint32_t lb = la; lb < LA; ++lb)
                    emit(la, lb);
        },
        [](const auto& gA, const auto&, uint32_t la, uint32_t lb) {
            Fp prod = fp_mul(gA[la], gA[lb]);
            return la != lb ? fp_add(prod, prod) : prod;
        },
        triangular, S ? S : 1, "square");
}

inline Cipher ct_div_const(const PubKey& pk, const Cipher& A, const Fp& k) {
    return ct_scale(pk, A, fp_inv(k));
}

} // namespace pvac