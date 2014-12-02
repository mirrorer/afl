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

   *** EXPERIMENTAL ARM VERSION ***

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


/* Examine and modify parameters to pass to 'as'. Note that the file name
   is always the last parameter passed by GCC, so we exploit this property
   to keep the code simple. */

static void edit_params(int argc, char** argv) {

  u8* tmp_dir = getenv("TMPDIR");

  if (!tmp_dir) tmp_dir = "/tmp";

  as_params = ck_alloc((argc + 1) * sizeof(u8*));

  memcpy(as_params, argv, argc * sizeof(u8*));

  as_params[0] = "as";
  as_params[argc] = 0;

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
  u8  now_instr = 0;
  u8  output_next = 0;

  if (input_file) {

    inf = fopen(input_file, "r");
    if (!inf) PFATAL("Unable to read '%s'", input_file);

  } else inf = stdin;

  outfd = open(modified_file, O_WRONLY | O_EXCL | O_CREAT, 0600);

  if (outfd < 0) PFATAL("Unable to write to '%s'", modified_file);

  outf = fdopen(outfd, "w");

  if (!outf) PFATAL("fdopen() failed");

  while (fgets(line, MAX_AS_LINE, inf)) {

    u8* label;

    /* Oh boy. The ARM version is extremely messy compared to Intel,
       because of the very limited range of immediate pointers within
       opcodes. When we inject the instrumentation, it's possible to
       push some labels / literal pools outside the range they were
       in when GCC first generated the code. This means several things:

       - We need to rewrite instructions such as ldr to movw + movt +
         ldr.

       - We need to do a similar but different hack for fld* / fst*.

       - We need to inject additional .ltorg sections and jump over
         them to ensure sufficient density of literal pools.

       - We need to be careful to not accidentally instrument .word
         literals that appear in the code segment.

       Whoever complains that x86 assembly is counterintuitive and ARM
       is user-friendly is probably at least a bit high.

     */

    /* Output instrumentation unless we're hitting a block of .word
       literals. */

    if (output_next) {

      if (strncmp(line, "\t.word", 6)) {
        fprintf(outf, trampoline_fmt, R(MAP_SIZE));
        ins_lines++;
      }

      output_next = 0;

    }

    /* Rewrite label-referencing ldr instructions. */

    if (now_instr && !strncmp(line, "\tldr", 4) && 
        (label = strstr(line, ", .L"))) {

      u8* reg = strchr(line + 4, '\t');

      label[0] = 0;

      fprintf(outf, "%s, =%s\n", line, label + 2);
      fprintf(outf, "%s, [%s]\n", line, reg);

      continue;

    }

    /* Do not-exactly-the-same for fld* and fst*. */

    if (now_instr &&
        (!strncmp(line, "\tfld", 4) || !strncmp(line, "\tfst", 4)) &&
        (label = strstr(line, ", .L"))) {

      label[0] = 0;

      fprintf(outf, "push {r12}\n");
      fprintf(outf, "ldr r12, =%s\n", label + 2);
      fprintf(outf, "%s, [r12]\n", line);
      fprintf(outf, "pop {r12}\n");

      continue;

    }

    fputs(line, outf);

    /* We only want to instrument the .text section. So, let's keep track
       of that in processed files. */

    if (line[0] == '\t' && line[1] == '.') {

      if (!strncmp(line + 2, "text\n", 5)) {
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

    /* If we're in the right mood for instrumenting, check for function
       names or conditional labels, decide what to do next. */

    if (now_instr && (
        (strstr(line, ":\n") && (line[0] == '.' ? isdigit(line[2]) : 1)) ||
        (line[0] == '\t' && line[1] == 'b' && line[2] == 'e'))) {

      output_next = 1;

    }


  }

  fputs(main_payload, outf);

  if (input_file) fclose(inf);
  fclose(outf);

  if (!ins_lines) WARNF("No instrumentation targets found.");
  else OKF("Successfully instrumented %u locations (seed = 0x%08x).",
           ins_lines, rand_seed);

}


/* Main entry point */

int main(int argc, char** argv) {

  s32 pid;
  int status;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "afl-as " cBRI VERSION cNOR " (" __DATE__ " " __TIME__ 
       ") by <lcamtuf@google.com>\n");

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

