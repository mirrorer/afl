/*
   american fuzzy lop - wrapper for GNU as
   ---------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   The sole purpose of this wrapper is to preprocess assembly files generated
   by GCC and inject the instrumentation bits included from afl-as.h. It is
   automatically invoked by the toolchain when compiling programs using
   afl-gcc.

   If AFL_QUIET is set, non-essential messages will not be shown. This is
   useful when dealing with wonky build systems.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include "afl-as.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>

static u8** as_params;          /* Parameters passed to the real 'as'   */

static u8*  input_file;         /* Originally specified input file      */
static u8*  modified_file;      /* Instrumented file for the real 'as'  */

static u32  rand_seed;          /* Random seed used for instrumentation */

static u8   be_quiet,           /* Quiet mode (no stderr output)        */
            use_64bit;          /* Output 64-bit instrumentation        */


/* Examine and modify parameters to pass to 'as'. Note that the file name
   is always the last parameter passed by GCC, so we exploit this property
   to keep the code simple. */

static void edit_params(int argc, char** argv) {

  u8* tmp_dir = getenv("TMPDIR");
  u32 i;

  if (!tmp_dir) tmp_dir = "/tmp";

  as_params = ck_alloc((argc + 1) * sizeof(u8*));

  memcpy(as_params, argv, argc * sizeof(u8*));

  as_params[0] = "as";
  as_params[argc] = 0;

  for (i = 1; i < argc; i++)
    if (!strcmp(as_params[i], "--64")) use_64bit = 1;

  input_file = as_params[argc - 1];

  if (input_file[0] == '-') {

    if (input_file[1]) FATAL("Incorrect use (not called through afl-gcc?)");
      else input_file = NULL;

  }

  modified_file = alloc_printf("%s/.afl-%u-%u.s", tmp_dir, getpid(),
                               (u32)time(NULL));

  as_params[argc - 1] = modified_file;

}


/* Process input file, generate modified_file. Insert instrumentation in all
   the appropriate places. */

static void add_instrumentation(void) {

  static u8 line[MAX_AS_LINE];

  FILE* inf;
  FILE* outf;
  s32 outfd;
  u32 ins_lines = 0;
  u8  now_instr = 0, force_inhibit = 0;

  if (input_file) {

    inf = fopen(input_file, "r");
    if (!inf) PFATAL("Unable to read '%s'", input_file);

  } else inf = stdin;

  outfd = open(modified_file, O_WRONLY | O_EXCL | O_CREAT, 0600);

  if (outfd < 0) PFATAL("Unable to write to '%s'", modified_file);

  outf = fdopen(outfd, "w");

  if (!outf) PFATAL("fdopen() failed");  

  while (fgets(line, MAX_AS_LINE, inf)) {

    fputs(line, outf);

    /* We only want to instrument the .text section. So, let's keep track
       of that in processed files. */

    if (line[0] == '\t' && line[1] == '.') {

      if (!strncmp(line + 2, "text\n", 5) ||
          !strncmp(line + 2, "section\t.text", 13)) {
        now_instr = 1; 
        continue; 
      }

      if (!strncmp(line + 2, "section\t", 8) ||
          !strncmp(line + 2, "bss\n", 4) ||
          !strncmp(line + 2, "data\n", 5)) {
        now_instr = 0;
        continue;
      }

    }

    if (strstr(line, ".code")) {

      if (strstr(line, ".code32")) force_inhibit = use_64bit;
      if (strstr(line, ".code64")) force_inhibit = !use_64bit;

    }

    /* If we're in the right mood for instrumenting, check for function
       names or conditional labels. This is a bit messy, but in essence,
       we want to catch:

         ^main:      - function entry point
         ^.L0:       - GCC branch label
         ^.LBB0_0:   - clang branch label
         ^\tjnz foo  - conditional branches

       ...but not:

         ^# BB#0:    - clang comments
         ^.Ltmp0:    - clang non-branch labels
         ^.LC0       - GCC non-branch labels
         ^\tjmp foo  - non-conditional jumps

     */

    if (!force_inhibit && now_instr && line[0] != '#' && (
        !strncmp(line, ".LBB", 4) ||
        (strstr(line, ":\n") && (line[0] == '.' ? isdigit(line[2]) : 1)) ||
        (line[0] == '\t' && line[1] == 'j' && line[2] != 'm'))) {

      /* Every function name and conditional label is given a random ID.
         This ID, XORed with the ID of the previously executed one, is used
         to selected a byte in the execution bitmap that is updated by the
         runtime instrumentation.

         All of this forms an almost-unique identifier of a particular state
         transition in program's control flow.

         If COVERAGE_ONLY is set, the instrumentation will use the current
         location only, and skip the XOR part. */

      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE));

      ins_lines++;

    }

  }

  if (ins_lines)
    fputs(use_64bit ? main_payload_64 : main_payload_32, outf);

  if (input_file) fclose(inf);
  fclose(outf);

  if (!be_quiet) {

    if (!ins_lines) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s-bit, %s mode, seed 0x%08x).",
             ins_lines, use_64bit ? "64" : "32",
             getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
             rand_seed);
 
  }

}


/* Main entry point */

int main(int argc, char** argv) {

  s32 pid;
  int status;

  struct timeval tv;
  struct timezone tz;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-as " cBRI VERSION cRST " (" __DATE__ " " __TIME__ 
         ") by <lcamtuf@google.com>\n");
 
  } else be_quiet = 1;

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It is a wrapper around GNU 'as',\n"
         "executed by the toolchain whenever using afl-gcc. You probably don't want to\n"
         "run this program directly.\n\n");

    exit(1);

  }

  gettimeofday(&tv, &tz);

  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

  srandom(rand_seed);

  edit_params(argc, argv);

  add_instrumentation();

  if (!(pid = fork())) {

    execvp(as_params[0], (char**)as_params);
    FATAL("Oops, failed to execute '%s' - check your PATH", as_params[0]);

  }

  if (pid < 0) PFATAL("fork() failed");

  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  unlink(modified_file);

  exit(WEXITSTATUS(status));

}

