
# encrypted ml inference

this example demonstrates a fully encrypted ml-scoring mechanism that is fully verified, all operations are homomorphic, and demonstrates the ability of the current PoC HFHE (pvac for verif) to work with similar mechanisms and be used in ML apps

we are beginning a series of examples (from simple to complex) that will focus on private models and private ml algos (truly private ones) because we see enormous potential in this

ml workflow here:

- **client**: keygen + encrypt feature vector
- **server**: homomorphic inference using `ct_add`, `ct_mul`, `ct_mul_const`, `ct_add_const`
- **client**: decrypt score + apply threshold

## model

mini credit scoring mlp (8 -> 4 -> 1 with cubic activation)

### features

| idx | field | unit | meaning |
|-----|-------|------|---------|
| 0 | age | years | applicant age |
| 1 | income_k | thousands | annual income |
| 2 | debt_k | thousands | outstanding debt |
| 3 | savings_k | thousands | savings |
| 4 | history_score | 0-100 | credit history |
| 5 | employment_years | years | job tenure |
| 6 | defaults | count | past payment defaults |
| 7 | open_accounts | count | active credit lines |

### decision logic
```
score < 0  ->  LOW_RISK   (negative cube = good indicators)
score > 0  ->  HIGH_RISK  (positive cube = risk factors)
```

## params

example uses reduced params for super-fast demo (for really fast models you will need to use the production HFHE version over the octra network)

```cpp
prm.m_bits = 1024;
prm.lpn_n  = 1024;
prm.edge_budget = 6000;
```

for prod use defaults from `Params` (lpn_n = 4096 and m_bits = 8192)

## build
```bash
make ml
```

## output
```
-- shimon_gershenson --
plain = -15072993
he = -15072993
match = OK
decision = LOW_RISK
ct = 496 layers, 4535 edges

-- sarah_katz --
plain = 64576
he = 64576
match = OK
decision = HIGH_RISK
ct = 496 layers, 4532 edges

etc...
```

## files

- `credit_scoring.cpp` - inference
- `credit_db.csv`  -  applicants