#include <pvac/pvac.hpp>
#include <iostream>

using namespace pvac;

int main() {
    std::cout << "== sk = 0 test ==\n\n";
    
    Params prm;
    PubKey pk;
    SecKey sk_real;
    keygen(prm, pk, sk_real);
    
    SecKey sk_zero;
    std::fill(sk_zero.prf_k.begin(), sk_zero.prf_k.end(), 0);
    sk_zero.lpn_s_bits.assign(sk_real.lpn_s_bits.size(), 0ull);
    
    uint64_t plaintext = 123456789;
    std::cout << "plaintext = " << plaintext << "\n";
    
    std::cout << "\n- case 1: enc(real) -> dec(real) ---\n";
    Cipher ct_real = enc_value(pk, sk_real, plaintext);
    uint64_t dec_real = dec_value(pk, sk_real, ct_real).lo;
    std::cout << "result: " << dec_real << (dec_real == plaintext ? " ok" : " wrong") << "\n";
    
    std::cout << "\n- case 2: enc(real) -> dec(zero)\n";
    uint64_t dec_zero = dec_value(pk, sk_zero, ct_real).lo;
    std::cout << "result: " << dec_zero << (dec_zero == plaintext ? " broken" : " garbage") << "\n";
    
    std::cout << "\n- case 3: enc(zero) -> dec( zero) -\n";
    Cipher ct_zero = enc_value(pk, sk_zero, plaintext);
    uint64_t dec_zero_zero = dec_value(pk, sk_zero, ct_zero).lo;
    std::cout << "result: " << dec_zero_zero << (dec_zero_zero == plaintext ? " ok (same key)" : " wrong") << "\n";
    
    std::cout << "\n- case 4: enc(zero) -> dec(real) -\n";
    uint64_t dec_real_from_zero = dec_value(pk, sk_real, ct_zero).lo;
    std::cout << "result: " << dec_real_from_zero << (dec_real_from_zero == plaintext ? " broken" : " garbage") << "\n";
    
    std::cout << "\n== res ==\n";
    if (dec_zero == plaintext || dec_real_from_zero == plaintext) {
        std::cout << "cross-key attack works (nah...)\n";
        return 1;
    } else {
        std::cout << "secure\n";
        return 0;
    }
}