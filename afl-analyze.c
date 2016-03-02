/*
   american fuzzy lop - file format analyzer
   -----------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A nifty utility that takes an input file and takes a stab at explaining
   its structure by observing how changes to it affect the execution path.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

static s32 child_pid;                 /* PID of the tested program         */

static u8* trace_bits;                /* SHM with instrumentation bitmap   */

static u8 *in_file,                   /* Analyzer input test case          */
          *prog_in,                   /* Targeted program input file       */
          *target_path,               /* Path to target binary             */
          *doc_path;                  /* Path to docs                      */

static u8* in_data;                   /* Input data for trimming           */

static u32 in_len,                    /* Input data length                 */
           boring_len,                /* Bytes that don't do anything      */
           orig_cksum,                /* Original checksum                 */
           total_execs,               /* Total number of execs             */
           exec_hangs,                /* Total number of hangs             */
           exec_tmout = EXEC_TIMEOUT; /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

static s32 shm_id,                    /* ID of the SHM region              */
           dev_null_fd = -1;          /* FD to /dev/null                   */

static u8  edges_only,                /* Ignore hit counts?                */
           use_stdin = 1;             /* Use stdin for program input?      */

static volatile u8
           stop_soon,                 /* Ctrl-C pressed?                   */
           child_timed_out;           /* Child timed out?                  */


/* Classify tuple counts. This is a slow & naive version, but good enough here. */

#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym),  AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym),  AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
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

  if (edges_only) {

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


/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(void) {

  u32* ptr = (u32*)trace_bits;
  u32  i   = (MAP_SIZE >> 2);

  while (i--) if (*(ptr++)) return 1;

  return 0;

}



/* Get rid of shared memory and temp files (atexit handler). */

static void remove_shm(void) {

  unlink(prog_in); /* Ignore errors */
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


/* Read initial file. */

static void read_initial_file(void) {

  struct stat st;
  s32 fd = open(in_file, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", in_file);

  if (fstat(fd, &st) || !st.st_size)
    FATAL("Zero-sized input file.");

  if (st.st_size >= TMIN_MAX_FILE)
    FATAL("Input file is too large (%u MB max)", TMIN_MAX_FILE / 1024 / 1024);

  in_len  = st.st_size;
  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  close(fd);

  OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

}


/* Write output file. */

static s32 write_to_file(u8* path, u8* mem, u32 len) {

  s32 ret;

  unlink(path); /* Ignore errors */

  ret = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (ret < 0) PFATAL("Unable to create '%s'", path);

  ck_write(ret, mem, len, path);

  lseek(ret, 0, SEEK_SET);

  return ret;

}


/* Handle timeout signal. */

static void handle_timeout(int sig) {

  child_timed_out = 1;
  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Execute target application. Returns exec checksum, or 0 if program
   times out. */

static u32 run_target(char** argv, u8* mem, u32 len, u8 first_run) {

  static struct itimerval it;
  int status = 0;

  s32 prog_in_fd;
  u32 cksum;

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  prog_in_fd = write_to_file(prog_in, mem, len);

  child_pid = fork();

  if (child_pid < 0) PFATAL("fork() failed");

  if (!child_pid) {

    struct rlimit r;

    if (dup2(use_stdin ? prog_in_fd : dev_null_fd, 0) < 0 ||
        dup2(dev_null_fd, 1) < 0 ||
        dup2(dev_null_fd, 2) < 0) {

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      PFATAL("dup2() failed");

    }

    close(dev_null_fd);
    close(prog_in_fd);

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

    }

    r.rlim_max = r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    execv(target_path, argv);

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  close(prog_in_fd);

  /* Configure timeout, wait for child, cancel timeout. */

  child_timed_out = 0;
  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  if (waitpid(child_pid, &status, 0) <= 0) FATAL("waitpid() failed");

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  MEM_BARRIER();

  /* Clean up bitmap, analyze exit condition, etc. */

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute '%s'", argv[0]);

  classify_counts(trace_bits);
  total_execs++;

  if (stop_soon) {
    SAYF(cLRD "\n+++ Analysis aborted by user +++\n" cRST);
    exit(1);
  }

  /* Always discard inputs that time out. */

  if (child_timed_out) {

    exec_hangs++;
    return 0;

  }

  cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

  /* We don't actually care if the target is crashing or not,
     except that when it does, the checksum should be different. */

  if (WIFSIGNALED(status) ||
      (WIFEXITED(status) && WEXITSTATUS(status) == MSAN_ERROR) ||
      (WIFEXITED(status) && WEXITSTATUS(status))) {

    cksum ^= 0xffffffff;

  }

  if (first_run) orig_cksum = cksum;

  return cksum;

}


/* Helper function to display a human-readable character. */

static void show_char(u8 val) {

  switch (val) {

    case 0 ... 32:
    case 127 ... 255: SAYF(cMGN "%02x " cNOR, val); break;

    default: SAYF(cCYA "%c  " cNOR, val);

  }

}


/* Constants used for describing byte runs. */

#define RUN_BORING 	0  /* A no-op run.                    */
#define RUN_VARIABLE	1  /* A run with variable checksums.  */
#define RUN_FIXED	2  /* A run with constant checksums.  */

/* Interpret and report a pattern in the input file. */

static void report_run(u32 st_pos, u32 len, u8 type, u8 boring_01) {

  u32 i;

  /* Start by showing a sample of data. */

  SAYF(cGRA "[%06u] " cNOR, st_pos);

  if (len <= 22 || len >= 44) {

    /* Very short or very long buffer. Start by showing head. */

    for (i = 0; i < MIN(len, 22); i++) show_char(in_data[st_pos + i]);
    SAYF("\n");

    /* Show tail, if any. */

    if (len >= 44) {

      u32 tail_pos = st_pos + len - 22;

      if (len > 44) SAYF(cGRA "  ....\n");
      SAYF(cGRA "[%06u] " cNOR, tail_pos);

      for (i = 0; i < 22; i++) show_char(in_data[tail_pos + i]);
      SAYF("\n");

    }

  } else {

    /* Intermediate length buffer (23-43 bytes). Show abridged
       single-line version. */

    u32 tail_pos = st_pos + len - 10;

    for (i = 0; i < 10; i++) show_char(in_data[st_pos + i]);
    SAYF(cGRA "(...) " cNOR);

    for (i = 0; i < 10; i++) show_char(in_data[tail_pos + i]);
    SAYF("\n");

  }

  /* Now, attempt to classify. */

  if (type == RUN_BORING) {

    SAYF(cBRI "         `-> Apparent no-op %s (len = %u)\n" cNOR, 
         (len == 1) ? "byte" : "blob", len);
    return;

  }

  if (type == RUN_VARIABLE) {

    SAYF(cBRI "         `-> Critical %s (len = %u)\n" cNOR,
         (len == 1) ? "byte" : "data blob", len);
    return;

  }

  if (len > 2 && boring_01) {

    SAYF(cBRI "         `-> Possibly no-op string (len = %u)\n" cNOR, len);
    return;

  }

  switch (len) {

    /* Lengths 2 and 4 may be checksums, magic values, or length fields. Let's
       be smart about classifying them. */

    case 2: {

        u16 val = *(u16*)(in_data + st_pos);

        if (val && (val <= in_len || SWAP16(val) <= in_len)) {

          SAYF(cBRI "         `-> Potential length field (len = 2)\n" cNOR);
          break;

        }

        if (in_data[st_pos] && in_data[st_pos + 1] &&
            !(in_data[st_pos] < 32 && in_data[st_pos + 1] < 32) &&
            !(isalnum(in_data[st_pos]) && isalnum(in_data[st_pos + 1])) &&
            !(in_data[st_pos] > 128 && in_data[st_pos + 1] > 128)) {

          SAYF(cBRI "         `-> Potential checksum or magic value (len = 2)"
               "\n" cNOR);

          break;

        }

        SAYF(cBRI "         `-> Atomically compared value (len = 2)\n" cNOR);
        break;

      }

    case 4: {

        u32 val = *(u32*)(in_data + st_pos);

        if (val && (val <= in_len || SWAP32(val) <= in_len)) {

          SAYF(cBRI "         `-> Potential length field (len = 2)\n" cNOR);
          break;

        }

        if (in_data[st_pos] && in_data[st_pos + 1] &&
            in_data[st_pos + 2] && in_data[st_pos + 3] &&
            !(in_data[st_pos] < 128 && in_data[st_pos + 1] < 128 &&
              in_data[st_pos + 2] < 128 && in_data[st_pos + 3] < 128) &&
            !(in_data[st_pos] > 128 && in_data[st_pos + 1] > 128 &&
              in_data[st_pos + 2] > 128 && in_data[st_pos + 3] > 128)) {

          SAYF(cBRI "         `-> Potential checksum or magic value (len = 4)"
               "\n" cNOR);

          break;

        }

        SAYF(cBRI "         `-> Atomically compared value (len = 4)\n" cNOR);
        break;

      }

    case 3: case 5 ... MAX_AUTO_EXTRA - 1:
      SAYF(cBRI "         `-> Atomically compared token (len = %u)\n" cNOR, len);
      break;

    default:
      SAYF(cLRD "         `-> Potential checksummed or encrypted blob "
           "(len = %u)\n" cNOR, len);
      break;

  }

}



/* Actually analyze! */

static void analyze(char** argv) {

  u32 i;
  u32 cur_run_len  = RUN_BORING, prev_ck01 = 0, cur_01_boring = 0;
  u8  cur_run_type = 0;

  ACTF("Analyzing input file...");

  SAYF("\n");

  /* Do walking byte flips. We flip all bits (xor 0xff) to get a definite
     answer if the byte is meaningful to the tested program; but later
     also flip the least significant bit (or 0x01) to better detect text-based
     syntax tokens.

     We use the 0x01-flip data in two ways:

     - To classify some runs of bytes with identical post-0x01-flip exec
       paths as corresponding to a single syntax token, a blob of checksummed
       data, etc.

     - To demote some such runs to "no-op strings" when 0xff flips produce
       different exec paths, but 0x01 flips consistently match baseline.

   */

  for (i = 0; i < in_len; i++) {

    u32 cksum_ff = 0, cksum_01 = 0;
    u8  saw_change;

    in_data[i] ^= 0xff;
    cksum_ff = run_target(argv, in_data, in_len, 0);

    if (cksum_ff != orig_cksum) {

      saw_change  = 1;

      in_data[i] ^= 0xfe;
      cksum_01 = run_target(argv, in_data, in_len, 0);
      in_data[i] ^= 0x01;

    } else {

      saw_change  = 0;
      in_data[i] ^= 0xff;
      prev_ck01   = 0;
      boring_len++;

    }

    /* Check for transitions between types of byte runs. */

    if (cur_run_len) {

      /* Previous run was boring, but we're now seeing checksum changes. */

      if (cur_run_type == RUN_BORING && saw_change) {

        report_run(i - cur_run_len, cur_run_len, RUN_BORING, 1);

        cur_run_len   = 0;
        cur_run_type  = RUN_VARIABLE;
        cur_01_boring = 0;

      } else

      /* Previous run was non-boring, but we no longer see changes. */

      if (cur_run_type != RUN_BORING && !saw_change) {

        report_run(i - cur_run_len, cur_run_len, cur_run_type,
                   (cur_01_boring == cur_run_len));

        cur_run_len   = 0;
        cur_run_type  = RUN_BORING;
        cur_01_boring = 0;

      } else

      /* Current run was fixed, but we're now seeing different cksums. */

      if (cur_run_type == RUN_FIXED && prev_ck01 != cksum_01) {

        if (cur_run_len > 1) {

          report_run(i - cur_run_len, cur_run_len, RUN_FIXED,
                     (cur_01_boring == cur_run_len));

          cur_run_len   = 0;
          cur_01_boring = 0;

        }

        cur_run_type = RUN_VARIABLE;

      } else 

      /* Current run was variable, but we're now seeing const cksums. */

      if (cur_run_type == RUN_VARIABLE && prev_ck01 == cksum_01) {

        if (cur_run_len > 1)
          report_run(i - cur_run_len, cur_run_len - 1, RUN_VARIABLE,
                     (cur_01_boring == cur_run_len));

        cur_run_len  = 1;
        cur_run_type = RUN_FIXED;

        if (prev_ck01 == orig_cksum) cur_01_boring = 1;
          else cur_01_boring = 0;
     
      }

    } else {

      if (saw_change) cur_run_type = RUN_VARIABLE;
        else cur_run_type = RUN_BORING;

    }

    if (cksum_01 == orig_cksum) cur_01_boring++;

    cur_run_len++;
    prev_ck01 = cksum_01;

  }

  /* Report any tail... */

  report_run(in_len - cur_run_len, cur_run_len, cur_run_type,
             (cur_01_boring == cur_run_len));

  SAYF("\n");

  OKF("Analysis complete. Interesting bits: %0.02f%% of the input file.",
      100.0 - ((double)boring_len * 100) / in_len);

  if (exec_hangs)
    WARNF(cLRD "Encountered %u timeouts - results may be skewed." cRST,
          exec_hangs);

}



/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  stop_soon = 1;

  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {

  u8* x;

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  if (!prog_in) {

    u8* use_dir = ".";

    if (!access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = getenv("TMPDIR");
      if (!use_dir) use_dir = "/tmp";

      prog_in = alloc_printf("%s/.afl-tmin-temp-%u", use_dir, getpid());

    }

  }

  /* Set sane defaults... */

  x = getenv("ASAN_OPTIONS");

  if (x && !strstr(x, "abort_on_error=1"))
    FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

  x = getenv("MSAN_OPTIONS");

  if (x && !strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
    FATAL("Custom MSAN_OPTIONS set without exit_code="
          STRINGIFY(MSAN_ERROR) " - please fix!");

  setenv("ASAN_OPTIONS", "abort_on_error=1:"
                         "detect_leaks=0:"
                         "allocator_may_return_null=1", 0);

  setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                         "msan_track_origins=0", 0);

}


/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

}


/* Detect @@ in args. */

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      /* Be sure that we're always using fully-qualified paths. */

      if (prog_in[0] == '/') aa_subst = prog_in;
      else aa_subst = alloc_printf("%s/%s", cwd, prog_in);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (prog_in[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i file       - input test case to be shrunk by the tool\n"

       "Execution control settings:\n\n"

       "  -f file       - input file read by the tested program (stdin)\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

       "Analysis settings:\n\n"

       "  -e            - look for edge coverage only, ignore hit counts\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}


/* Find binary. */

static void find_binary(u8* fname) {

  u8* env_path = 0;
  struct stat st;

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);

    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4) break;

      ck_free(target_path);
      target_path = 0;

    }

    if (!target_path) FATAL("Program '%s' not found or not executable", fname);

  }

}


/* Fix up argv for QEMU. */

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  /* Now we need to actually find qemu for argv[0]. */

  new_argv[2] = target_path;
  new_argv[1] = "--";

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {

    target_path = new_argv[0] = BIN_PATH "/afl-qemu-trace";
    return new_argv;

  }

  FATAL("Unable to find 'afl-qemu-trace'.");

}


/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u8  mem_limit_given = 0, timeout_given = 0, qemu_mode = 0;
  char** use_argv;

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  SAYF(cCYA "afl-analyze " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  while ((opt = getopt(argc,argv,"+i:f:m:t:eQ")) > 0)

    switch (opt) {

      case 'i':

        if (in_file) FATAL("Multiple -i options not supported");
        in_file = optarg;
        break;

      case 'f':

        if (prog_in) FATAL("Multiple -f options not supported");
        use_stdin = 0;
        prog_in   = optarg;
        break;

      case 'e':

        if (edges_only) FATAL("Multiple -e options not supported");
        edges_only = 1;
        break;

      case 'm': {

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 't':

        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        exec_tmout = atoi(optarg);

        if (exec_tmout < 10 || optarg[0] == '-')
          FATAL("Dangerously low value of -t");

        break;

      case 'Q':

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        qemu_mode = 1;
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_file) usage(argv[0]);

  setup_shm();
  setup_signal_handlers();

  set_up_environment();

  find_binary(argv[optind]);
  detect_file_args(argv + optind);

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  SAYF("\n");

  read_initial_file();

  ACTF("Performing dry run (mem limit = %llu MB, timeout = %u ms%s)...",
       mem_limit, exec_tmout, edges_only ? ", edges only" : "");

  run_target(use_argv, in_data, in_len, 1);

  if (child_timed_out)
    FATAL("Target binary times out (adjusting -t may help).");

  if (!anything_set()) FATAL("No instrumentation detected.");

  analyze(use_argv);

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

