/*
   american fuzzy lop - persistent mode example
   --------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file demonstrates the high-performance "persistent mode" that may be
   suitable for fuzzing certain fast and well-behaved libraries, provided that
   they are stateless or that their internal state can be easily reset
   across runs.

   To make this work, the library and this shim need to be compiled in LLVM
   mode using afl-clang-fast (other compiler wrappers will *not* work); and
   afl-fuzz must be called with AFL_PERSISTENT set.

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

/* This constant specifies the number of inputs to process before restarting.
   This is optional, but helps limit the impact of memory leaks and similar
   hiccups. */

#define PERSIST_MAX 1000

unsigned int persist_cnt;


/* Main entry point. */

int main(int argc, char** argv) {

  char buf[100]; /* Example-only buffer, you'd replace it with other global or
                    local variables appropriate for your use case. */

try_again:

  /*** PLACEHOLDER CODE ***/

  /* STEP 1: Fully re-initialize all critical variables. In our example, this
             involves zeroing buf[], our input buffer. */

  memset(buf, 0, 100);

  /* STEP 2: Read input data. When reading from stdin, no special preparation
             is required. When reading from a named file, you need to close the
             old descriptor and reopen the file first!

             Beware of reading from buffered FILE* objects such as stdin. Use
             raw file descriptors or call fopen() / fdopen() in every pass. */

  read(0, buf, 100);

  /* STEP 3: This is where we'd call the tested library on the read data. Here,
             we just have some trivial inline code that faults on 'foo!'. */

  if (buf[0] == 'f') {
    printf("one\n");
    if (buf[1] == 'o') {
      printf("two\n");
      if (buf[2] == 'o') {
        printf("three\n");
        if (buf[3] == '!') {
          printf("four\n");
          abort();
        }
      }
    }
  }

  /*** END PLACEHOLDER CODE ***/

  /* STEP 4: To signal successful completion of a run, we need to deliver
             SIGSTOP to our own process, then loop to the very beginning
             once we're resumed by the supervisor process. We do this only
             if AFL_PERSISTENT is set to retain normal behavior when the
             program is executed directly; and take note of PERSIST_MAX. */

  if (getenv("AFL_PERSISTENT") && persist_cnt++ < PERSIST_MAX) {

    raise(SIGSTOP);
    goto try_again;

  }

  /* If AFL_PERSISTENT not set or PERSIST_MAX exceeded, exit normally. */

  return 0;

}
