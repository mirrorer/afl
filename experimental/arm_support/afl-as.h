/*
   american fuzzy lop - injectable parts
   -------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file houses the assembly-level instrumentation injected into fuzzed
   programs. The instrumentation stores pairs of data: identifiers of the
   currently executing line and the line that executed immediately before.

   *** EXPERIMENTAL ARM VERSION ***

 */

#ifndef _HAVE_AFL_AS_H
#define _HAVE_AFL_AS_H

#include "config.h"
#include "types.h"

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL((x))

static const u8* trampoline_fmt =

  "\n"
  "/* --- AFL TRAMPOLINE --- */\n"
  "\n"
  "  push {r0-r6, lr}\n"
  "  movw r0, #%u\n"
  "  bl   __afl_maybe_log\n"
  "\n"
  "  b 1f\n"
  ".ltorg\n"
  "  1:\n"
  "\n"
  "  pop  {r0-r6, lr}\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

static const u8* main_payload = 

  /* Register map for the main logging code:

     r0 - current code location (later cur XOR prev)
     r1 - address of SHM (later final tuple write ptr)
     r2 - pointer to prev code location
     r3 - loaded previous code location
     r4 - saved ALU flags

     r5 - pointer to setup failure data
     r6 - setup failure value

     For a discussion of the overall operating principles of the
     injected code, see the comments in the x86 version instead.

   */

  "\n"
  "/* --- AFL MAIN PAYLOAD --- */\n"
  "\n"
  ".text\n"
  "\n"
  "__afl_maybe_log:\n"
  "\n"
  "  mrs r4, APSR\n"
  "\n"
  "  ldr r1, =__afl_area_ptr\n"
  "  ldr r1, [r1]\n"
  "  cmp r1, #0\n"
  "  beq __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  ldr r2, =__afl_prev_loc\n"
  "  ldr r3, [r2]\n"
  "  str r0, [r2]\n"
  "\n"
  "  eor r0, r0, r3\n"
  "  add r1, r1, r0\n"
  "\n"
  "  ldrb r0, [r1]\n"
  "  add  r0, #1\n"
  "  strb r0, [r1]\n"
  "\n"
  "__afl_return:\n"
  "\n"
  "  msr APSR_nzcvq, r4\n"
  "  blx lr\n"
  "\n"
  "__afl_setup:\n"
  "\n"
  "  ldr  r5, =__afl_setup_failure\n"
  "  ldr  r6, [r5]\n"
  "  cmp  r6, #1\n"
  "  beq  __afl_return\n"
  "\n"

  /* Register map for the following setup / fork server code:

     r1  - address of SHM (returned to caller)
     r5  - pointer to setup failure data
     r10 - temporary copy of SHM address
     r11 - child PID

     Other registers: scratch.

   */

  "  push {r0, r2-r12, lr}\n"
  "\n"
  "  ldr r0, =.AFL_SHM_ID\n"
  "  bl  getenv\n"
  "  cmp r0, #0\n"
  "  beq __afl_setup_abort\n"
  "\n"
  "  bl atoi\n"
  "\n"
  "  mov r1, #0\n"
  "  mov r2, #0\n"
  "  bl  shmat\n"
  "  cmp r0, #-1\n"
  "  beq __afl_setup_abort\n"
  "\n"
  "  ldr r1, =__afl_area_ptr\n"
  "  str r0, [r1]\n"
  "  mov r10, r0\n"
  "\n"
  "__afl_forkserver:\n"
  "\n"
  "  mov r0, #" STRINGIFY(FORKSRV_FD + 1) "\n"
  "  ldr r1, =__afl_temp\n"
  "  mov r2, #4\n"
  "  bl  write\n"
  "  cmp r0, #4\n"
  "  bne __afl_fork_resume\n"
  "\n"
  "__afl_fork_wait_loop:\n"
  "\n"
  "  mov r0, #" STRINGIFY(FORKSRV_FD) "\n"
  "  ldr r1, =__afl_temp\n"
  "  mov r2, #4\n"
  "  bl  read\n"
  "  cmp r0, #4\n"
  "  bne __afl_die\n"
  "\n"
  "  bl  fork\n"
  "  cmp r0, #0\n"
  "  blt __afl_die\n"
  "  beq __afl_fork_resume\n"
  "\n"
  "  ldr r2, =__afl_fork_pid\n"
  "  str r0, [r2]\n"
  "  mov r11, r0\n"
  "\n"
  "  mov r0, #" STRINGIFY(FORKSRV_FD + 1) "\n"
  "  ldr r1, =__afl_fork_pid\n"
  "  mov r2, #4\n"
  "  bl  write\n"
  "  cmp r0, #4\n"
  "  bne __afl_die\n"
  "\n"
  "  mov r0, r11\n"
  "  ldr r1, =__afl_temp\n"
  "  mov r2, #2\n"
  "  bl  waitpid\n"
  "  cmp r0, #0\n"
  "  ble __afl_die\n"
  "\n"
  "  mov r0, #" STRINGIFY(FORKSRV_FD + 1) "\n"
  "  ldr r1, =__afl_temp\n"
  "  mov r2, #4\n"
  "  bl  write\n"
  "  cmp r0, #4\n"
  "  bne __afl_die\n"
  "\n"
  "  b __afl_fork_wait_loop\n"
  "\n"
  "__afl_fork_resume:\n"
  "\n"
  "  mov r1, r10\n"
  "  pop {r0, r2-r12, lr}\n"
  "  b   __afl_store\n"
  "\n"
  "__afl_setup_abort:\n"
  "\n"
  "  mov r0, #1\n"
  "  str r0, [r5]\n"
  "  pop {r0, r2-r12, lr}\n"
  "  b   __afl_return\n"
  "\n"
  "__afl_die:\n"
  "\n"
  "  mov r0, #0\n"
  "  bl  exit\n"
  "\n"
  ".AFL_VARS:\n"
  "\n"
  "  .comm   __afl_area_ptr, 4, 4\n"
  "  .comm   __afl_prev_loc, 4, 4\n"
  "  .comm   __afl_setup_failure, 1, 4\n"
  "  .comm   __afl_saved_flags, 2, 4\n"
  "  .comm   __afl_fork_pid, 4, 4\n"
  "  .comm   __afl_temp, 4, 4\n"
  "\n"
  ".AFL_SHM_ID:\n"
  "  .string \"" SHM_ENV_VAR "\"\n"
  "\n"
  "/* --- END -- */\n";

#endif /* !_HAVE_AFL_AS_H */

