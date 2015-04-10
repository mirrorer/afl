/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#include "../config.h"
#include "../types.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>


/* Globals needed by the injected instrumentation. */

u8* __afl_area_ptr;
u16 __afl_prev_loc;


/* Create some decoy memory as early as possible to get us through any
   code that runs before main(). */

static void __afl_pre_map(void) {

  __afl_area_ptr = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  /* Whoops. */

  if (__afl_area_ptr == (void *)-1) exit(1);

}


/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, get rid
     of the early-stage map. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    munmap(__afl_area_ptr, MAP_SIZE);
    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */
    if (__afl_area_ptr == (void *)-1) exit(1);

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  u8 tmp[4];

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    s32 child_pid;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(1);

    /* Once woken up, create a clone of our process. */

    child_pid = fork();
    if (child_pid < 0) exit(1);

    /* In child process: close fds, resume execution. */

    if (!child_pid) {

      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      return;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(1);
    if (waitpid(child_pid, &status, WUNTRACED) < 0) exit(1);

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);

  }

}


/* Proper initialization routine. */

static void __afl_init() {
  __afl_map_shm();
  __afl_start_forkserver();
}


/* Now, the tricky part. We want to get __afl_area_ptr assigned as soon
   as possible, so that custom assembly that calls C code from .init
   doesn't cause segfaults (hello, OpenSSL). But at this stage, getenv()
   will not work, so we just use the dummy handler. */

__attribute__((section(".preinit_array"), used))
  static void (*__afl_preinit_f)(void) = __afl_pre_map;

/* With this out of the way, we can wait until just before main() to
   do the whole shmat() and forkserver thing. */

__attribute__((section(".init_array"), used))
  static void (*__afl_init_f)(void) = __afl_init;
