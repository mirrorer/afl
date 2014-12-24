/*
   american fuzzy lop - vaguely configurable bits
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#include "types.h"

/******************************************************
 *                                                    *
 *  Settings that may be of interest to power users:  *
 *                                                    *
 ******************************************************/

/* Comment out to disable terminal colors: */

#define USE_COLOR

/* Comment out to disable fancy ANSI boxes and use poor man's 7-bit UI: */

#define FANCY_BOXES

/* Default timeout for fuzzed code (milliseconds): */

#define EXEC_TIMEOUT        1000

/* Default memory limit for child process (MB): */

#ifndef __x86_64__ 
#  define MEM_LIMIT         25
#else
#  define MEM_LIMIT         50
#endif /* ^!__x86_64__ */

/* Number of calibration cycles per every new test case (and for test
   cases that show variable behavior): */

#define CAL_CYCLES          10
#define CAL_CYCLES_LONG     50

/* Number of subsequent hangs before abandoning an input file: */

#define HANG_LIMIT          250

/* Maximum number of unique hangs or crashes to record: */

#define KEEP_UNIQUE_HANG    500
#define KEEP_UNIQUE_CRASH   5000

/* Baseline number of random tweaks during a single 'havoc' stage: */

#define HAVOC_CYCLES        5000

/* Maximum multiplier for the above (should be a power of two, beware
   of 32-bit int overflows): */

#define HAVOC_MAX_MULT      16

/* Maximum stacking for havoc-stage tweaks. The actual value is calculated
   like this: 

   n = random between 0 and HAVOC_STACK_POW2
   stacking = 2^n

   In other words, the default (n = 7) produces 1, 2, 4, 8, 16, 32, 64, or
   128 stacked tweaks: */

#define HAVOC_STACK_POW2    7

/* Caps on block sizes for cloning and deletion operations. Each of these
   ranges has a 33% probability of getting picked: */

#define HAVOC_BLK_SMALL     32
#define HAVOC_BLK_MEDIUM    128
#define HAVOC_BLK_LARGE     1500

/* Likelihood of using non-favored inputs when there are pending, non-fuzzed
   test cases (and when there is nothing new pending). This is expressed as
   percentage: */

#define SKIP_TO_NEW_PROB    99
#define SKIP_NFAV_PROB      90

/* Splicing cycle count: */

#define SPLICE_CYCLES       20

/* Nominal per-splice havoc cycle length: */

#define SPLICE_HAVOC        500

/* Maximum value for integer addition / subtraction stages: */

#define ARITH_MAX           35

/* Limits for the test case trimmer. The absolute minimum chunk size; and
   the starting and ending divisors for chopping up the input file: */

#define TRIM_MIN_BYTES      4
#define TRIM_START_STEPS    16
#define TRIM_END_STEPS      1024

/* Maximum size of input file, in bytes (keep under 100MB): */

#define MAX_FILE            (1 * 1024 * 1024)

/* Maximum "extra" token size (-x), in bytes: */

#define MAX_EXTRA_FILE      128

/* Maximum number of extras to still carry out deterministic steps: */

#define MAX_DET_EXTRAS      500

/* UI refresh frequency (Hz): */

#define UI_TARGET_HZ        4

/* Fuzzer stats file and plot update intervals (sec): */

#define STATS_UPDATE_SEC    60
#define PLOT_UPDATE_SEC     5

/* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */

#define AVG_SMOOTHING       25

/* Sync interval (havoc cycles): */

#define SYNC_INTERVAL       5

/* List of interesting values to use in fuzzing. */

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */

/***********************************************************
 *                                                         *
 *  Really exotic stuff you probably don't want to touch:  *
 *                                                         *
 ***********************************************************/

/* Call count interval between reseeding the libc PRNG from /dev/urandom: */

#define RESEED_RNG          10000

/* Maximum line length passed from GCC to 'as': */

#define MAX_AS_LINE         8192

/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

/* Other less interesting, internal-only variables. */

#define CLANG_ENV_VAR       "__AFL_CLANG_MODE"
#define AS_LOOP_ENV_VAR     "__AFL_AS_LOOPCHECK"

/* Distinctive exit code used to indicate failed execution: */

#define EXEC_FAIL           85
#define MSAN_ERROR          86

/* Designated file desciptors for forkserver commands (the application will
   use FORKSRV_FD and FORKSRV_FD + 1): */

#define FORKSRV_FD          198

/* Fork server init timeout multiplier: we'll wait the user-selected
   timeout plus this much for the fork server to spin up. */

#define FORK_WAIT_MULT      10

/* Calibration timeout adjustments, to be a bit more generous when resuming
   fuzzing sessions or trying to calibrate already-added internal finds.
   The first value is a percentage, the other is in milliseconds: */

#define CAL_TMOUT_PERC      125
#define CAL_TMOUT_ADD       50

/* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
   2; you probably want to keep it under 18 or so for performance reasons
   (adjusting AFL_INST_RATIO when compiling is probably a better way to solve
   problems). You need to recompile the target binary after changing this -
   otherwise, SEGVs may ensue. */

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

/* Maximum allocator request size (keep well under INT_MAX): */

#define MAX_ALLOC           0x40000000

/* Uncomment this to use inferior line-coverage-based instrumentation. Note
   that you need to recompile the target binary for this to have any effect: */

// #define COVERAGE_ONLY

/* Uncomment this to use instrumentation data to record newly discovered paths,
   but do not use them as seeds for fuzzing. This is useful for conveniently
   measuring coverage that could be attaine by a "dumb" fuzzing algorithm: */

// #define IGNORE_FINDS

#endif /* ! _HAVE_CONFIG_H */
