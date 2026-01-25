CXX := g++
CXXFLAGS := -std=c++17 -O2 -march=native -Wall -Wextra -I./include
DEBUG_FLAGS := -g -O0 -DPVAC_DEBUG
SANITIZE_FLAGS := -fsanitize=address,undefined
BUILD := build
TESTS := tests
EXAMPLES := examples

all: $(BUILD)/test_main

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_main: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_hg: $(TESTS)/test_hg.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_main_debug: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) -o $@ $<

$(BUILD)/test_main_san: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) $(SANITIZE_FLAGS) -o $@ $

$(BUILD)/basic_usage: $(EXAMPLES)/basic_usage.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_prf: $(TESTS)/test_prf.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct: $(TESTS)/test_ct.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_depth: $(TESTS)/test_depth.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_sigma: $(TESTS)/test_sigma.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_zero: $(TESTS)/test_zero.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_lpn: $(TESTS)/test_lpn.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_fp_core: $(TESTS)/test_fp_core.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_bitvec: $(TESTS)/test_bitvec.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_prf_ext: $(TESTS)/test_prf_ext.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_sigma_lpn: $(TESTS)/test_sigma_lpn.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_noise_struct: $(TESTS)/test_noise_struct.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct_fuzz: $(TESTS)/test_ct_fuzz.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct_safe: $(TESTS)/test_ct_safe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_aes_ctr: $(TESTS)/test_aes_ctr.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_struct: $(TESTS)/test_struct.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_struct_v2: $(TESTS)/test_struct_v2.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_compactness: $(TESTS)/test_compactness.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

debug: $(BUILD)/test_main_debug
sanitize: $(BUILD)/test_main_san
examples: $(BUILD)/basic_usage
test_zero: $(BUILD)/test_zero
test_lpn: $(BUILD)/test_lpn
test_fp_core: $(BUILD)/test_fp_core
test_bitvec: $(BUILD)/test_bitvec
test_prf_ext: $(BUILD)/test_prf_ext
test_sigma_lpn: $(BUILD)/test_sigma_lpn
test_noise_struct: $(BUILD)/test_noise_struct
test_ct_fuzz: $(BUILD)/test_ct_fuzz
test_ct_safe: $(BUILD)/test_ct_safe
test_aes_ctr: $(BUILD)/test_aes_ctr
test_struct: $(BUILD)/test_struct
test_struct_v2: $(BUILD)/test_struct_v2
test_compactness: $(BUILD)/test_compactness


test: $(BUILD)/test_main
	@./$(BUILD)/test_main

test-v: $(BUILD)/test_main
	@PVAC_DBG=2 ./$(BUILD)/test_main

test-q: $(BUILD)/test_main
	@PVAC_DBG=0 ./$(BUILD)/test_main

test-hg: $(BUILD)/test_hg
	@./$(BUILD)/test_hg

test-prf: $(BUILD)/test_prf
	@./$(BUILD)/test_prf

test-ct: $(BUILD)/test_ct
	@./$(BUILD)/test_ct

test-depth: $(BUILD)/test_depth
	@./$(BUILD)/test_depth

test-sigma: $(BUILD)/test_sigma
	@./$(BUILD)/test_sigma

test-zero: $(BUILD)/test_zero
	@./$(BUILD)/test_zero

test-lpn: $(BUILD)/test_lpn
	@./$(BUILD)/test_lpn

test-fp-core: $(BUILD)/test_fp_core
	@./$(BUILD)/test_fp_core

test-bitvec: $(BUILD)/test_bitvec
	@./$(BUILD)/test_bitvec

test-prf-ext: $(BUILD)/test_prf_ext
	@./$(BUILD)/test_prf_ext

test-sigma-lpn: $(BUILD)/test_sigma_lpn
	@./$(BUILD)/test_sigma_lpn

test-noise-struct: $(BUILD)/test_noise_struct
	@./$(BUILD)/test_noise_struct

test-ct-fuzz: $(BUILD)/test_ct_fuzz
	@./$(BUILD)/test_ct_fuzz

test-ct-safe: $(BUILD)/test_ct_safe
	@./$(BUILD)/test_ct_safe

test-aes-ctr: $(BUILD)/test_aes_ctr
	@./$(BUILD)/test_aes_ctr

test-struct: $(BUILD)/test_struct
	@./$(BUILD)/test_struct

test-struct-v2: $(BUILD)/test_struct_v2
	@./$(BUILD)/test_struct_v2

test-compactness: $(BUILD)/test_compactness
	@./$(BUILD)/test_compactness


clean:
	rm -rf $(BUILD) pvac_metrics.csv

help:
	@echo "targets: all test test-v test-q test-hg debug sanitize examples clean"
	@echo "env: PVAC_DBG=0|1|2"

.PHONY: all test test-v test-q test-hg clean help