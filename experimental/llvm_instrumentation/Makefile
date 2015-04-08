#
# american fuzzy lop - LLVM instrumentation
# -----------------------------------------
#
# Written by Laszlo Szekeres <lszekeres@google.com>
#
# Copyright 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# *** EXPERIMENTAL VERSION ***
#

LLVM_CONFIG = llvm-config

CC          = `$(LLVM_CONFIG) --bindir`/clang
CXX         = `$(LLVM_CONFIG) --bindir`/clang++
CXXFLAGS    = `$(LLVM_CONFIG) --cxxflags`
LDFLAGS     = `$(LLVM_CONFIG) --ldflags`

all: afl_cov.so afl_cov_rt.o afl_setup.o

# LLVM instrumentation pass

afl_cov.so: afl_cov.o
	$(CXX) $(LDFLAGS) -shared -o $@ $<

afl_cov.o: afl_cov.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# AFL runtime

afl_cov_rt.o: afl_cov_rt.c
	$(CC) -g -c -o $@ $<

# AFL init function (forkserver): could be moved to afl_cov_rt.c

afl_setup.o: afl_setup.s
	as -o $@ $<

.PHONY: clean
clean:
	rm -f *.o afl_cov.so
