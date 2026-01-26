CXX = g++
CXXFLAGS = -std=c++17 -O3 -march=native -fopenmp

OPENFHE_INC = -I/usr/local/include/openfhe -I/usr/local/include/openfhe/core \
              -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/binfhe
OPENFHE_LIB = -L/usr/local/lib -lOPENFHEpke -lOPENFHEbinfhe -lOPENFHEcore -pthread

PVAC_INC = -I../pvac/include

HEADERS = common.hpp bench_bfv.hpp bench_bgv.hpp bench_ckks.hpp bench_tfhe.hpp bench_binfhe.hpp bench_pvac.hpp

all: bench

bench: main.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -o bench main.cpp $(OPENFHE_INC) $(PVAC_INC) $(OPENFHE_LIB)

clean:
	rm -f bench results/*.csv

.PHONY: all clean