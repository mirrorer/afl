/*
   american fuzzy lop - run program, display map
   ---------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   If AFL_SINK_OUTPUT is set, output from the traced program will be
   redirected to /dev/null. AFL_QUIET inhibits all non-fatal messages
   from the tool, too.

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
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

static s32 child_pid;                 /* PID of the tested program         */

static u8* trace_bits;                /* SHM with instrumentation bitmap   */

static s32 shm_id;                    /* ID of the SHM region              */

static u8  sink_output,               /* Sink program output               */
           be_quiet;                  /* Quiet mode (tuples & errors only) */

/* Classify tuple counts. */

#define AREP4(_sym) (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym) AREP4(_sym), AREP4(_sym)
#define AREP16(_sym) AREP8(_sym), AREP8(_sym)
#define AREP32(_sym) AREP16(_sym), AREP16(_sym)
#define AREP64(_sym) AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

static u8 count_class_lookup[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 4,
  /* 4 - 7:      +4 */ AREP4(8),
  /* 8 - 15:     +8 */ AREP8(16),
  /* 16 - 31:   +16 */ AREP16(32),
  /* 32 - 127:  +96 */ AREP64(64), AREP32(64),
  /* 128+:     +128 */ AREP128(128)

};

static void classify_counts(u8* mem) {

  u32 i = MAP_SIZE;

  if (getenv("AFL_EDGES_ONLY")) {

    while (i--) {

      if (*mem) *mem = 1;
      mem++;

    }

  } else {

    while (i--) {

      *mem = count_class_lookup[*mem];
      mem++;

    }

  }

}


/* Show all recorded tuples. */

static inline void show_tuples(void) {

  u8* current = (u8*)trace_bits;
  u32 i;

  classify_counts(trace_bits);

  for (i = 0; i < MAP_SIZE; i++) {

    if (*current) SAYF("%05u/%u\n", i, *current);

    current++;

  }

}


/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(void) {

  u32* ptr = (u32*)trace_bits;
  u32  i   = (MAP_SIZE >> 2);

  while (i--) if (*(ptr++)) return 1;

  return 0;

}



/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {
  shmctl(shm_id, IPC_RMID, NULL);
}


/* Configure shared memory. */

static void setup_shm(void) {

  u8* shm_str;

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}


/* Execute target application. */

static void run_target(char** argv) {

  int status = 0;

  child_pid = fork();

  if (child_pid < 0) PFATAL("fork() failed");

  if (!child_pid) {

    if (sink_output) {

      s32 fd = open("/dev/null", O_RDWR);

      if (fd < 0) PFATAL("Cannot open /dev/null");

      if (dup2(fd, 1) < 0 || dup2(fd, 2) < 0) PFATAL("dup2() failed");

      close(fd);

    }

    execvp(argv[0], argv);

    PFATAL("Unable to execute '%s'", argv[0]);

  }

  if (waitpid(child_pid, &status, WUNTRACED) <= 0) FATAL("waitpid() failed");

  if (WIFSIGNALED(status))
    SAYF("+++ Killed by signal %u +++\n", WTERMSIG(status));

}



/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s /path/to/traced_app [ ... ]\n\n"

       "Shows all instrumentation tuples recorded when executing a binary compiled\n"
       "with afl-gcc or afl-clang. You can set AFL_SINK_OUTPUT=1 to sink all output\n"
       "from the executed program, AFL_QUIET=1 to suppress non-fatal messages from\n"
       "this tool, or AFL_EDGES_ONLY to only display edges, not hit counts.\n\n",
       argv0);

  exit(1);

}


/* Main entry point */

int main(int argc, char** argv) {

  if (!getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-showmap " cBRI VERSION cRST " (" __DATE__ " " __TIME__ 
         ") by <lcamtuf@google.com>\n");

  } else be_quiet = 1;

  if (argc < 2) usage(argv[0]);

  setup_shm();

  if (getenv("AFL_SINK_OUTPUT")) sink_output = 1;

  if (!be_quiet && !sink_output)
    SAYF("\n-- Program output begins --\n");  

  run_target(argv + 1);

  if (!be_quiet && !sink_output)
    SAYF("-- Program output ends --\n");  

  if (!anything_set()) FATAL("No instrumentation data recorded");

  if (!be_quiet) SAYF(cBRI "\nTuples recorded:\n\n" cRST);

  show_tuples();

  exit(0);

}

