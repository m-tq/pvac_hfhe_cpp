# (PoC HFHE against everything) fhe benchmark suite 

we use a testbed for full evaluation and comparison of all parameters and performance in our internal workflow, we recently decided to make it completely open source

we compare pvac_hfhe in its current proof of concept version which does not claim prod speed,it is provided as-is for hypothesis testing, bounty programs, and academic work we also compare an early research PoC against production optimized implementations from OpenFHE (some tests may be incomplete)

pvac_hfhe (even the earliest concept) outperforms prod implemented rlwe in scalar arithmetic (multiplication is 2.9 up to 14.3x faster, addition is 10 -87x faster, dot prod is 7.5x faster, ct size is 6 - 85x smaller for fresh encryptions, compared to bit level fhe (tfhe/fhew) the speedup reaches insane *789000x  for 64 bit operations, basically we compared against fhew to achieve the same good academic presentation as the early FHEW PoC

*can't be compared but it's worth noting for fun

for this work we use a DigitalOcean droplet with the following parameters:

- cpu: DO Premium AMD 8 core 2.0GHz
- ram: 32GB
- os: Ubuntu 24.04 LTS
- compiler: g++ -O3 -march=native
- pvac_hfhe: research poc (unoptimized)

## schemes

| scheme | type | impl | security |
|--------|------|------|----------|
| BFV | rlwe, exact int | OpenFHE 1.2 | 128-bit |
| BGV | rlwe, exact int | OpenFHE 1.2 | 128-bit |
| CKKS | rlwe, approximate | OpenFHE 1.2 | 128-bit |
| TFHE | bit-level | OpenFHE 1.2 | 128-bit |
| FHEW | bit-level, ginx | OpenFHE 1.2 | 128-bit |
| PVAC_HFHE | lpn, exact uint64 | poc/research | 128-bit (est) |

---

## 1. scalar mul (ct * ct)

| scheme | mode | mul (ms) | vs pvac_hfhe |
|--------|------|----------|---------|
| PVAC_HFHE | scalar | 2.47 | 1.0x |
| BFV | shallow (d = 1) | 7.23 | 2.9x slower |
| BFV | leveled (d = 5) | 18.28 | 7.4x slower |
| BGV | leveled | 17.61 | 7.1x slower |
| CKKS | leveled | 35.23 | 14.3x slower |

### BFV plaintext modulus

| mod | bits | ring | mul (ms) | ct_size |
|-----|------|------|----------|---------|
| 65537 | 17 | 8192 | 8.81 | 384 KB |
| 786433 | 20 | 8192 | 8.12 | 384 KB |
| 2013265921 | 31 | 16384 | 19.75 | 1024 KB |

btw, BFV requires ntt friendly primes, pvac_hfhe works with arbitrary uint64

---

## 2. scalar add (ct + ct)

| scheme | add (ms) | vs pvac |
|--------|----------|---------|
| PVAC_HFHE | 0.012 | 1.0x |
| BFV | 0.124 | 10x slower |
| BGV | 0.552 | 46x slower |
| CKKS | 1.050 | 87x slower |

---

## 3. ciphertext size

### fresh ct

| scheme | mode | ct_size | vs pvac |
|--------|------|---------|---------|
| PVAC_HFHE | scalar | 42 KB | 1.0x |
| BFV | shallow | 256 KB | 6x larger |
| BFV | leveled | 1024 KB | 24x larger |
| BGV | leveled | 1792 KB | 43x larger |
| CKKS | leveled | 3584 KB | 85x larger |

### PVAC_HFHE ct growth with depth

| depth | time (ms) | ct_size | growth |
|-------|-----------|---------|--------|
| d0 | - | 42 KB | 1.0x |
| d1 | 2.68 | 34 KB | 0.8x |
| d2 | 10.34 | 136 KB | 3.2x |
| d3 | 31.46 | 441 KB | 10.5x |
| d4 | 97.11 | 1359 KB | 32x |
| d5 | 285.83 | 4112 KB | 98x |

hfhe ct exceeds bfv at d4.

---

## 4. depth

| depth | PVAC_HFHE | BFV | BGV | CKKS | fastest |
|-------|------|-----|-----|------|---------|
| d1 | 2.68 | 19.54 | 17.40 | 35.85 | PVAC 7.3x |
| d2 | 10.34 | 14.38 | 15.11 | 31.22 | PVAC 1.4x |
| d3 | 31.46 | 13.98 | 14.39 | 30.71 | BFV 2.3x |
| d4 | 97.11 | 13.84 | 11.10 | 21.83 | BGV 8.7x |
| d5 | 285.83 | 11.37 | 9.50 | 18.93 | BGV 30x |

PoC: exponential degradation,  rlwe: near constant via modulus switching etc

---

## 5. dot product (scalar vectors)

| n | PVAC_HFHE | BFV | BGV | CKKS | PVAC_HFHE speedup |
|---|------|-----|-----|------|--------------|
| 4 | 9.61 | 73.24 | 74.55 | 156.53 | 7.6x |
| 8 | 19.08 | 149.68 | 152.55 | 308.24 | 7.8x |
| 16 | 38.49 | 297.02 | 294.65 | 605.52 | 7.7x |
| 32 | 80.27 | 598.94 | 626.17 | 1218.69 | 7.5x |

---

## 6. polynomial

f(x) = 3x^3 + 2x^2 + 5x + 7 (depth-3)

| scheme | time (ms) | vs pvac |
|--------|-----------|---------|
| PVAC_HFHE | 62.88 | 1.0x |
| BFV | 71.72 | 1.1x slower |
| BGV | 92.79 | 1.5x slower |
| CKKS | 182.35 | 2.9x slower |

---

## 7. bit-level fhe

### nand gate

| scheme | mode | keygen (ms) | nand (ms) |
|--------|------|-------------|-----------|
| FHEW | ginx | 374 | 79.30 |
| TFHE | std128 | 440 | 81.71 |
| binfhe_ap | ap | 785 | 102.56 |

### derived 64-bit mul

(estimated nand latency x 24576 gates (schoolbook andno optimization))

| scheme | 64-bit mul | vs PVAC_HFHE |
|--------|------------|---------|
| PVAC | 2.47 ms | 1.0x |
| FHEW | 32.48 min | 789000x slower |
| TFHE | 33.47 min | 813000x slower |
| binfhe_ap | 42.01 min | 1020000x slower |

it may not be very indicative because it solves different problems but we decided to include it to display as honestly as possible the current situation for the Poc hfhe versus the product scheme with 10+ y of research

---

## 8. simd / batch throughput

### rlwe simd

| scheme | slots | mul (ms) | per slot (us) |
|--------|-------|----------|---------------|
| BFV | 8192 | 17.85 | 2.18 |
| CKKS | 4096 | 35.49 | 8.66 |

### pvac HFHE parallel

| ops | seq (ms) | par (ms) | speedup | throughput |
|-----|----------|----------|---------|------------|
| 512 | 1391 | 189 | 7.4x | 2711 ops/s |
| 2048 | 4963 | 795 | 6.2x | 2575 ops/s |
| 8192 | 19904 | 2608 | 7.6x | 3141 ops/s |

### comparison

| mode | ops/s | relative |
|------|-------|----------|
| BFV simd (8192 slots) | ~459,000 | 146x faster |
| PVAC_HFHE parallel (8 threads) | ~3,141 | 1.0x |

---

## 9. keygen / encrypt

| scheme | keygen (ms) | encrypt (ms) | decrypt (ms) |
|--------|-------------|--------------|--------------|
| BFV | 38.43 | 10.91 | 2.54 |
| BGV | 62.03 | 12.70 | 3.48 |
| CKKS | 143.61 | 23.34 | 10.37 |
| PVAC_HFHE | 858.95 | 84.11 | 13.38 |

pvac_hfhe keygen 22x slower, encrypt 8x slower, for proof of concept, this is ok, it happens because of the cumbersome approach to initialization, but it also has its advantages (for example, it only needs to be called once from the wallet with the private key).

---

## 10. key sizes

| scheme | pk_size | ct_size |
|--------|---------|---------|
| PVAC_HFHE | 8 MB | 42 KB |
| BFV | - | 1024 KB |
| BGV | - | 1792 KB |
| CKKS | - | 3584 KB |

---

## mini-summary 

### pvac_hfhe advantages

| metric | improvement |
|--------|-------------|
| scalar mul vs bfv shallow | 2.9x faster |
| scalar mul vs bfv leveled | 7.4x faster |
| scalar mul vs ckks | 14.3x faster |
| scalar add | 10-87x faster |
| dot product | 7.5-7.8x faster |
| ct size (fresh) | 6-85x smaller |
| vs bit-level fhe | 789,000x faster |

### pvac_hfhe limitations
(only valid for PoC HFHE due to cumbersome debugging sys)

| metric | limitation |
|--------|------------|
| deep circuits (d >= 3) | 2-30x slower |
| ct growth | exponential |
| simd throughput | 146x slower |
| keygen | 22x slower |
| encrypt | 8x slower |


## methodology

- 128-bit security
- timing: steady_clock
- stats: mean of n runs with warmup
- verif: correctness checked
- ckks accuracy: err < 0.01

### caveats

1. pvac-hfhe is an early PoC with no optimizations at all (there are only SIMD instructions for matrices and other small things)
2. openfhe is production optimized (10+ years)
3. bit-level 64 bit mul is derived estimate
4. pvac security based on lpn (less studied than RLWE btw, but we are doing our best to close that gap)

---

to run the tests, you'll need a whole bunch of stuff, but it's potentially worth it, you'll need a full installation of OpenFHE, a build of Léo Ducas's FHEW, and you'll also need to compile pvac

so if you have a few hours of free time and you love C++ like we do, this might be of interest

## run

```bash
make
./bench -all
cat results/all.csv
```


## here are the results you will get locally:
```
root@test-fhe:~/fhe_bench/benchmarks# mkdir -p results && make && ./bench -all
g++ -std=c++17 -O3 -march=native -fopenmp -o bench main.cpp -I/usr/local/include/openfhe -I/usr/local/include/openfhe/core -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/binfhe -I../pvac/include -L/usr/local/lib -lOPENFHEpke -lOPENFHEbinfhe -lOPENFHEcore -pthread
fhe benchmarks
________________________________________
targets: bfv bgv binfhe ckks fhew pvac tfhe 
output: results/all.csv
omp_threads = 8

bfv (scalar, mod 65537)
________________________________________
security = 128-bit, plaintext = mod 65537 (17-bit)
keygen = 38.43 ms
encrypt = 10.91 ms, decrypt = 2.54 ms
verify: 7*6 = 42, 7+6 = 13 (ok)
mul = 18.28 ms, add = 0.12 ms
depth: d1 = 19.54ms d2 = 14.38ms d3 = 13.98ms d4 = 13.84ms d5 = 11.37ms 
dot: dot4 = 73.24ms dot8 = 149.68ms dot16 = 297.02ms dot32 = 598.94ms 
polynomial = 71.72 ms
ct_size_est = 1024 KB (polys = 2, towers = 4, ring = 16384)

bfv (simd)
________________________________________
slots = 8192
rotate_keygen = 61.68 ms
mul = 17.85 ms (2.18 us/slot)
dot8192 = 133.05 ms

bfv plaintext modulus comparison
________________________________________

mod = 17bit (65537)
ring_dim = 8192
mul = 8.81 ms (stddev = 4.28)
ct_size_est = 384 KB (towers = 3, ring = 8192)

mod = 20bit (786433)
ring_dim = 8192
mul = 8.12 ms (stddev = 2.50)
ct_size_est = 384 KB (towers = 3, ring = 8192)

mod = 31bit (2013265921)
ring_dim = 16384
mul = 19.75 ms (stddev = 2.59)
ct_size_est = 1024 KB (towers = 4, ring = 16384)

note: BFV requires NTT-friendly primes (p-1 divisible by 2*ring_dim)
PVAC has no such constraint - works with arbitrary uint64

bfv (shallow, depth=1)
________________________________________
ring_dim = 8192
verify: 7*6 = 42
mul = 7.23 ms (stddev = 5.17)
ct_size_est = 256 KB

bgv (scalar, mod 65537)
________________________________________
security = 128-bit, plaintext = mod 65537 (17-bit)
keygen = 62.03 ms
encrypt = 12.70 ms, decrypt = 3.48 ms
verify: 7*6 = 42, 7+6 = 13 (ok)
mul = 17.61 ms, add = 0.55 ms
depth: d1 = 17.40ms d2 = 15.11ms d3 = 14.39ms d4 = 11.10ms d5 = 9.50ms 
dot: dot4 = 74.55ms dot8 = 152.55ms dot16 = 294.65ms dot32 = 626.17ms 
polynomial = 92.79 ms
ct_size_est = 1792 KB (polys = 2, towers = 7, ring = 16384)

ckks (scalar, approximate)
________________________________________
security = 128-bit, type = approximate
keygen = 143.61 ms
encrypt = 23.34 ms, decrypt = 10.37 ms
verify: 7*6 = 42.00 (err=0.00), 7+6 = 13.00 (err=0.00) (ok)
mul = 35.23 ms, add = 1.05 ms
depth: d1 = 35.85ms d2 = 31.22ms d3 = 30.71ms d4 = 21.83ms d5 = 18.93ms 
dot: dot4 = 156.53ms dot8 = 308.23ms dot16 = 605.52ms dot32 = 1218.69ms 
polynomial = 182.35 ms
ct_size_est = 3584 KB (polys = 2, towers = 7, ring = 32768)

ckks (simd)
________________________________________
slots = 4096
rotate_keygen = 231.50 ms
mul = 35.49 ms (8.66 us/slot)
dot4096 = 373.64 ms

tfhe (bit-level, bootstrap per gate)
________________________________________
security = 128-bit
keygen = 439.77 ms
encrypt_1bit = 20.06 us, decrypt_1bit = 2.58 us
nand = 81.71 ms
mul_64bit_derived = 33.47 min
add_64bit_derived = 26.15 sec

fhew (bit-level, ginx mode)
________________________________________
security = 128-bit, mode = ginx
keygen = 373.99 ms
nand = 79.30 ms
mul_64bit_derived = 32.48 min

binfhe_ap (openfhe binfhe, ap mode)
________________________________________
security = 128-bit, mode = ap
keygen = 785.11 ms
nand = 102.56 ms
mul_64bit_derived = 42.01 min

pvac (scalar, exact uint64, poc)
________________________________________
keygen = 858.95 ms
security = 128-bit (lpn), lpn_n = 4096
impl = pclmul t_us = 1787.30
encrypt = 84.11 ms, decrypt = 13.38 ms
verify: 7*6 = 42, 7+6 = 13
mul = 2.47 ms, add = 0.01 ms
depth (time/ct_size): d1=2.68ms/34KB(ok) d2=10.34ms/136KB(ok) d3=31.46ms/441KB(ok) d4=97.11ms/1359KB(ok) d5=285.83ms/4112KB(ok) 
dot: dot4 = 9.61ms dot8 = 19.08ms dot16 = 38.49ms dot32 = 80.27ms 
polynomial = 62.88 ms
ct_size = 42 KB, pk_size = 8 MB

pvac (parallel throughput)
________________________________________
threads = 8
ops = 512: seq = 1391.03ms, par = 188.86ms, speedup = 7.37x, throughput = 2710.99 ops/s
ops = 2048: seq = 4962.62ms, par = 795.21ms, speedup = 6.24x, throughput = 2575.41 ops/s
ops = 8192: seq = 19904.02ms, par = 2607.98ms, speedup = 7.63x, throughput = 3141.13 ops/s

________________________________________
done. saved to results/all.csv
root@test-fhe:~/fhe_bench/benchmarks# cat results/all.csv
scheme,mode,op,mean,stddev,unit,n
bfv,scalar,keygen,38.4269,1.83478,ms,10
bfv,scalar,encrypt,10.912,0.358104,ms,50
bfv,scalar,decrypt,2.53961,0.187732,ms,50
bfv,scalar,mul,18.2788,4.11367,ms,50
bfv,scalar,add,0.124013,0.0111941,ms,50
bfv,scalar,depth1,19.5356,0,ms,1
bfv,scalar,depth2,14.3763,0,ms,1
bfv,scalar,depth3,13.981,0,ms,1
bfv,scalar,depth4,13.8372,0,ms,1
bfv,scalar,depth5,11.3745,0,ms,1
bfv,scalar,dot4,73.2356,7.1367,ms,5
bfv,scalar,dot8,149.682,9.82773,ms,5
bfv,scalar,dot16,297.019,10.7301,ms,5
bfv,scalar,dot32,598.944,25.8472,ms,5
bfv,scalar,polynomial,71.7218,2.35397,ms,10
bfv,scalar,ct_size_est_bytes,1.04858e+06,0,bytes,1
bfv,simd,rotate_keygen,61.6808,0,ms,1
bfv,simd,mul,17.8548,0.586675,ms,50
bfv,simd,mul_per_slot_us,2.17954,0,us,1
bfv,simd,dot8192,133.047,1.53564,ms,10
bfv,17bit,mul,8.80741,4.28474,ms,50
bfv,17bit,ct_size_est_bytes,393216,0,bytes,1
bfv,20bit,mul,8.11649,2.49567,ms,50
bfv,20bit,ct_size_est_bytes,393216,0,bytes,1
bfv,31bit,mul,19.7503,2.59334,ms,50
bfv,31bit,ct_size_est_bytes,1.04858e+06,0,bytes,1
bfv,shallow,mul,7.22595,5.16919,ms,50
bfv,shallow,ct_size_est_bytes,262144,0,bytes,1
bgv,scalar,keygen,62.0255,2.51092,ms,10
bgv,scalar,encrypt,12.695,0.425174,ms,50
bgv,scalar,decrypt,3.47912,0.23724,ms,50
bgv,scalar,mul,17.612,1.09816,ms,50
bgv,scalar,add,0.552388,0.0399797,ms,50
bgv,scalar,depth1,17.3975,0,ms,1
bgv,scalar,depth2,15.109,0,ms,1
bgv,scalar,depth3,14.388,0,ms,1
bgv,scalar,depth4,11.1001,0,ms,1
bgv,scalar,depth5,9.50312,0,ms,1
bgv,scalar,dot4,74.5541,1.91863,ms,5
bgv,scalar,dot8,152.552,2.41426,ms,5
bgv,scalar,dot16,294.647,7.66063,ms,5
bgv,scalar,dot32,626.165,13.8713,ms,5
bgv,scalar,polynomial,92.7947,5.97436,ms,10
bgv,scalar,ct_size_est_bytes,1.83501e+06,0,bytes,1
ckks,scalar,keygen,143.613,7.88688,ms,10
ckks,scalar,encrypt,23.3378,1.16429,ms,50
ckks,scalar,decrypt,10.3669,0.990674,ms,50
ckks,scalar,mul,35.2345,3.5964,ms,50
ckks,scalar,add,1.04964,0.0663965,ms,50
ckks,scalar,depth1,35.8472,0,ms,1
ckks,scalar,depth2,31.2208,0,ms,1
ckks,scalar,depth3,30.7127,0,ms,1
ckks,scalar,depth4,21.8297,0,ms,1
ckks,scalar,depth5,18.9339,0,ms,1
ckks,scalar,dot4,156.526,6.91078,ms,5
ckks,scalar,dot8,308.235,8.8257,ms,5
ckks,scalar,dot16,605.517,4.35161,ms,5
ckks,scalar,dot32,1218.69,29.8511,ms,5
ckks,scalar,polynomial,182.349,3.26154,ms,10
ckks,scalar,ct_size_est_bytes,3.67002e+06,0,bytes,1
ckks,simd,rotate_keygen,231.5,0,ms,1
ckks,simd,mul,35.4894,3.35441,ms,50
ckks,simd,mul_per_slot_us,8.66441,0,us,1
ckks,simd,dot4096,373.639,16.3547,ms,10
tfhe,bit,keygen,439.773,879.51,ms,5
tfhe,bit,encrypt_1bit,20.0579,6.83268,us,50
tfhe,bit,decrypt_1bit,2.58356,0.549856,us,50
tfhe,bit,nand,81.708,2.85233,ms,50
tfhe,bit,mul_64bit_derived,2.00806e+06,0,ms,1
tfhe,bit,add_64bit_derived,26146.6,0,ms,1
fhew,bit,keygen,373.992,747.932,ms,5
fhew,bit,nand,79.2976,0.768636,ms,50
fhew,bit,mul_64bit_derived,1.94882e+06,0,ms,1
binfhe_ap,bit,keygen,785.106,1570.16,ms,5
binfhe_ap,bit,nand,102.564,1.69785,ms,50
binfhe_ap,bit,mul_64bit_derived,2.5206e+06,0,ms,1
pvac,scalar,keygen,858.953,16.2382,ms,10
pvac,scalar,encrypt,84.1074,2.07639,ms,50
pvac,scalar,decrypt,13.3761,0.180103,ms,50
pvac,scalar,mul,2.47403,0.133738,ms,50
pvac,scalar,add,0.0121177,0.00245914,ms,50
pvac,scalar,depth1,2.68092,0,ms,1
pvac,scalar,depth1_ct_bytes,34880,0,bytes,1
pvac,scalar,depth2,10.3428,0,ms,1
pvac,scalar,depth2_ct_bytes,139280,0,bytes,1
pvac,scalar,depth3,31.457,0,ms,1
pvac,scalar,depth3_ct_bytes,452480,0,bytes,1
pvac,scalar,depth4,97.1119,0,ms,1
pvac,scalar,depth4_ct_bytes,1.39208e+06,0,bytes,1
pvac,scalar,depth5,285.832,0,ms,1
pvac,scalar,depth5_ct_bytes,4.21088e+06,0,bytes,1
pvac,scalar,dot4,9.61315,0.324681,ms,5
pvac,scalar,dot8,19.076,0.364868,ms,5
pvac,scalar,dot16,38.4917,0.924917,ms,5
pvac,scalar,dot32,80.2705,0.708586,ms,5
pvac,scalar,polynomial,62.8789,4.02088,ms,10
pvac,scalar,ct_size_bytes,43280,0,bytes,1
pvac,scalar,pk_size_bytes,8.38861e+06,0,bytes,1
pvac,parallel,mul_512_seq_ms,1391.03,0,ms,1
pvac,parallel,mul_512_par_ms,188.861,0,ms,1
pvac,parallel,mul_512_throughput,2710.99,0,ops_per_sec,1
pvac,parallel,mul_2048_seq_ms,4962.62,0,ms,1
pvac,parallel,mul_2048_par_ms,795.212,0,ms,1
pvac,parallel,mul_2048_throughput,2575.41,0,ops_per_sec,1
pvac,parallel,mul_8192_seq_ms,19904,0,ms,1
pvac,parallel,mul_8192_par_ms,2607.98,0,ms,1
pvac,parallel,mul_8192_throughput,3141.13,0,ops_per_sec,1
```