/*
   american fuzzy lop - wrapper for GCC
   ------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This program is a drop-in replacement for GCC. The most common way of using
   it is to pass the path to afl-gcc via the CC or CXX variable when invoking
   ./configure.

   The wrapper needs to know the path to afl-as (renamed to 'as'). The default
   is /usr/local/lib/afl/. A convenient way to specify alternative directories
   would be to set AFL_PATH.

   If AFL_HARDEN is set, the wrapper will compile the target app with various
   hardening options that may help detect memory management issues more
   reliably. Depending on config.h, this may include enabling ASAN.

   If AFL_QUIET is set, non-essential messages will not be shown. This is
   useful when dealing with wonky build systems.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  as_path;                /* Path to the AFL 'as' wrapper      */
static u8** gcc_params;             /* Parameters passed to the real GCC */
static u32  gcc_par_cnt = 1;        /* Param count, including argv0      */
static u8   be_quiet;               /* Quiet mode                        */


/* Try to find our "fake" GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort. */

static void find_as(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/as", afl_path);

    if (!access(tmp, X_OK)) {
      as_path = afl_path;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);

  }

  if (!access(AFL_PATH "/as", X_OK)) {
    as_path = AFL_PATH;
    return;
  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8* dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/as", dir);

    if (!access(tmp, X_OK)) {
      as_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);

  }

  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");
 
}


/* Copy argv to gcc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0;
  u8 *name;

  gcc_params = ck_alloc((argc + 12) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (strcmp(name, "afl-g++") && strcmp(name, "afl-c++")) {

    u8* alt_cc = getenv("AFL_CC");
    gcc_params[0] = alt_cc ? alt_cc : (u8*)"gcc";

  } else {

    u8* alt_cxx = getenv("AFL_CXX");
    gcc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++";

  }

  while (--argc) {
    u8* cur = *(++argv);

    if (!strncmp(cur, "-B", 2)) {

      if (!be_quiet) WARNF("-B is already set, overriding");

      if (!cur[2] && argc) { argc--; argv++; }
      continue;

    }

    if (!strcmp(cur, "-pipe")) continue;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    gcc_params[gcc_par_cnt++] = cur;

  }

  gcc_params[gcc_par_cnt++] = "-B";
  gcc_params[gcc_par_cnt++] = as_path;
  gcc_params[gcc_par_cnt++] = "-g";

  if (getenv("AFL_HARDEN") || getenv("AFL_HARDEN_NOASAN")) {

    gcc_params[gcc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      gcc_params[gcc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (getenv("AFL_HARDEN")) {

#ifdef USE_ASAN
    gcc_params[gcc_par_cnt++] = "-fsanitize=address";
#endif /* USE_ASAN */

  }

  gcc_params[gcc_par_cnt] = NULL;

}


/* Main entry point */

int main(int argc, char** argv) {

  /* The as_nl part is a crude check from being called from within ./configure.
     Some sketchy ./configure checks can fail if the compiler outputs anything
     to stderr, even if the compilation succeeds and return code is 0. Yuck. */

  if (!getenv("AFL_QUIET") && !getenv("as_nl")) {

    SAYF(cCYA "afl-gcc " cBRI VERSION cRST " (" __DATE__ " " __TIME__
         ") by <lcamtuf@google.com>\n");

  } else be_quiet = 1;

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in\n"
         "replacement for gcc, letting you recompile third-party code with\n"
         "the required runtime instrumentation. A common use pattern would be:\n\n"

         "  CC=/usr/local/bin/afl-gcc ./configure\n\n");

    exit(1);

  }


  find_as(argv[0]);

  edit_params(argc, argv);

  execvp(gcc_params[0], (char**)gcc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", gcc_params[0]);

  return 0;

}

