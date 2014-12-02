/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

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
#include <ctype.h>

#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>


/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

static u8 *in_dir,                    /* Directory with initial testcases */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir,                   /* Working & output directory       */
          *sync_dir,                  /* Synchronization directory        */
          *sync_id,                   /* Fuzzer ID                        */
          *use_banner,                /* Display banner                   */
          *in_bitmap;                 /* Input bitmap                     */

static u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u64 mem_limit = MEM_LIMIT;     /* Memory cap for child (MB)        */

static u32 stats_update_freq = 1;     /* Stats update frequency (execs)   */

static u8  skip_deterministic,        /* Skip deterministic stages?       */
           force_deterministic,       /* Force deterministic stages?      */
           use_splicing,              /* Recombine input files?           */
           dumb_mode,                 /* Run in non-instrumented mode?    */
           score_changed,             /* Scoring for favorites changed?   */
           kill_signal,               /* Signal that killed the child     */
           resuming_fuzz,             /* Resuming an older fuzzing job?   */
           timeout_given,             /* Specific timeout given?          */
           not_on_tty;                /* stdout is not a tty              */

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom_fd,            /* Persistent fd for /dev/urandom   */
           dev_null_fd,               /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd;                /* Fork server status pipe (read)   */

static s32 forksrv_pid,               /* PID of the fork server           */
           child_pid = -1;            /* PID of the fuzzed program        */

static u8* trace_bits;                /* SHM with instrumentation bitmap  */
static u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
           virgin_hang[MAP_SIZE],     /* Bits we haven't seen in hangs    */
           virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

static s32 shm_id;                    /* ID of the SHM region             */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                   clear_screen,      /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */

static u32 queued_paths,              /* Total number of queued testcases */
           queued_variable,           /* Testcases with variable behavior */
           queued_at_start,           /* Total number of initial inputs   */
           queued_later_on,           /* Items queued after 1st cycle     */
           queued_imported,           /* Items imported via -S            */
           queued_favored,            /* Paths deemed favorable           */
           queued_with_cov,           /* Paths with new coverage bytes    */
           pending_not_fuzzed,        /* Queued but not done yet          */
           pending_favored,           /* Pending favored paths            */
           cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
           cur_depth,                 /* Current path depth               */
           max_depth,                 /* Max path depth                   */
           useless_at_start,          /* Number of useless starting paths */
           current_entry;             /* Current queue entry ID           */

static u64 total_crashes,             /* Total number of crashes          */
           unique_crashes,            /* Crashes with unique signatures   */
           total_hangs,               /* Total number of hangs            */
           unique_hangs,              /* Hangs with unique signatures     */
           total_execs,               /* Total execve() calls             */
           start_time,                /* Unix start time (ms)             */
           last_path_time,            /* Time for most recent path (ms)   */
           last_crash_time,           /* Time for most recent crash (ms)  */
           last_hang_time,            /* Time for most recent hang (ms)   */
           queue_cycle,               /* Queue round counter              */
           cycles_wo_finds,           /* Cycles without any new paths     */
           trim_execs,                /* Execs done to trim input files   */
           bytes_trim_in,             /* Bytes coming into the trimmer    */
           bytes_trim_out;            /* Bytes coming outa the trimmer    */

static u32 subseq_hangs;              /* Number of hangs in a row         */

static u8 *stage_name = "init",       /* Name of the current fuzz stage   */
          *stage_short,               /* Short stage name                 */
          *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max;      /* Stage progression                */
static s32 splicing_with = -1;        /* Splicing with which test case?   */

static u32 syncing_case;              /* Syncing with case #...           */

static s32 stage_cur_byte,            /* Byte offset of current stage op  */
           stage_cur_val;             /* Value used for stage op          */

static u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[14],           /* Patterns found per fuzz stage    */
           stage_cycles[14];          /* Execs per fuzz stage             */

static u32 rand_cnt = RESEED_RNG;     /* Random number counter            */

static u64 total_cal_us,              /* Total calibration time (us)      */
           total_cal_cycles;          /* Total calibration cycles         */

static u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
           total_bitmap_entries;      /* Number of bitmaps counted        */

struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_done,                       /* Calibration completed?           */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size;                    /* Number of bits set in bitmap     */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_bits;                     /* Trace bits, if kept              */
  u32 tc_ref;                         /* Trace bits ref count             */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_1k;        /* 1000 elements ahead              */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top, /* Top of the list                  */
                          *queue_p1k; /* Previous 1k marker               */

static struct queue_entry*
  top_rated[MAP_SIZE << 3];           /* Top entries for every bitmap bit */

/* Interesting values, as per config.h */

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* Fuzzing stages */

enum {
  STAGE_FLIP1,
  STAGE_FLIP2,
  STAGE_FLIP4,
  STAGE_FLIP8,
  STAGE_FLIP16,
  STAGE_FLIP32,
  STAGE_ARITH8,
  STAGE_ARITH16,
  STAGE_ARITH32,
  STAGE_INTEREST8,
  STAGE_INTEREST16,
  STAGE_INTEREST32,
  STAGE_HAVOC,
  STAGE_SPLICE
};

/* Stage value types */

enum {
  STAGE_VAL_NONE,
  STAGE_VAL_LE,
  STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
  FAULT_NONE,
  FAULT_HANG,
  FAULT_CRASH,
  FAULT_ERROR,
  FAULT_NOINST,
  FAULT_NOBITS
};


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}


/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

  if (!rand_cnt--) {

    u32 seed[2];

    if (read(dev_urandom_fd, &seed, sizeof(seed)) != sizeof(seed))
      PFATAL("Short read from /dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}


#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) f_loc = pos;
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif /* !IGNORE_FINDS */


/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8* DI(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 100, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 10, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 100, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 10, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 100, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 10, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 100, "%0.01fT", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe float. Similar to the above, except with a single 
   static buffer. */

static u8* DF(double val) {

  static u8 tmp[16];

  if (val < 99.99) {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.9) {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);

}


/* Describe integer as memory size. */

static u8* DMS(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 100, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 10, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 100, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 10, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 100, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 10, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 100, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8* DTD(u64 cur_ms, u64 event_ms) {

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;

}


/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

static void mark_as_det_done(struct queue_entry* q) {

  u8* fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;

}


/* Mark / unmark as redundant. This is not used for restoring state, but may
   be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_paths/%s", out_dir, fn + 1);

  if (state) {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}


/* Append new test case to the queue. */

static void add_to_queue(u8* fname, u32 len, u8 passed_det) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = fname;
  q->len          = len;
  q->depth        = cur_depth + 1;
  q->passed_det   = passed_det;

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else queue_p1k = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  if (!(queued_paths % 1000)) {

    queue_p1k->next_1k = q;
    queue_p1k = q;

  }

  if (queue_cycle > 1) queued_later_on++;

  last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

static void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_bits);
    ck_free(q);
    q = n;

  }

}


/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

static inline void write_bitmap(void) {

  u8* fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  s32 fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  if (write(fd, virgin_bits, MAP_SIZE) != MAP_SIZE)
    PFATAL("Short write to '%s'", fname);

  close(fd);
  ck_free(fname);

}


/* Read bitmap from file. This is for the -B option again. */

static inline void read_bitmap(u8* fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  if (read(fd, virgin_bits, MAP_SIZE) != MAP_SIZE)
    PFATAL("Short read from '%s'", fname);

  close(fd);

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0. */

static inline u8 has_new_bits(u8* virgin_map) {

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);
  u8   ret = 0;

  while (i--) {

    if (*current & *virgin) {

      if (ret < 2) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        if ((cur[0] && vir[0] == 255) || (cur[1] && vir[1] == 255) ||
            (cur[2] && vir[2] == 255) || (cur[3] && vir[3] == 255)) ret = 2;
        else ret = 1;

      }

      *virgin &= ~*current;
    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) write_bitmap();

  return ret;

}


/* Count the number of bits set in the provided bitmap. This is used just
   for the status screen. */

static inline u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;

  }

  return ret;

}


/* Count the number of non-255 bytes in the provided bitmap. Likewise,
   just a helper function to help with the visuals. */

static inline u32 count_non_255_bytes(u8* mem) {

  u32 i  = MAP_SIZE;
  u32 ret = 0;

  while (i--) if (*(mem++) != 255) ret++;

  return ret;

}


/* Destructively simplify trace by eliminating hit count information. */

static void simplify_trace(u8* mem) {

  u32 i = MAP_SIZE;

  while (i--) {
    if (*mem) *mem = 128; else *mem = 1;
    mem++;
  }

}


/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. We put tuple hit counts
   into several buckets: 1, 2, 3, 4 to 7, 8 to 15, 16 to 31, 32 to 127, and
   128+. */

static void classify_counts(u8* mem) {

  u32 i = MAP_SIZE;

  while (i--) {

    switch (*mem) {
      case 3:           *mem = (1 << 2); break;
      case 4 ... 7:     *mem = (1 << 3); break;
      case 8 ... 15:    *mem = (1 << 4); break;
      case 16 ... 31:   *mem = (1 << 5); break;
      case 32 ... 127:  *mem = (1 << 6); break;
      case 128 ... 255: *mem = (1 << 7); break;
    }

    mem++;

  }

}


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {
  shmctl(shm_id, IPC_RMID, NULL);
}


/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every position in the bitmap. We win that slot if there is no previous
   contender, or if the contender has fewer trace_bits[] set when we do. */

static void update_bitmap_score(struct queue_entry* q) {

  u32 i;

  /* For every bit set in trace_bits[], see if there are any other hits
     and how they compare. */

  for (i = 0; i < (MAP_SIZE << 3); i++)
    if (trace_bits[i >> 3] & (1 << (i & 7))) {

       if (top_rated[i]) {

         if (top_rated[i]->bitmap_size >= q->bitmap_size) continue;

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_bits);
           top_rated[i]->trace_bits = 0;
         }

       }

       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_bits) {
         q->trace_bits = ck_alloc(MAP_SIZE);
         memcpy(q->trace_bits, trace_bits, MAP_SIZE);
       }

       score_changed = 1;

     }

}


/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries and adds their trace_bits[] to a temporary
   bitmap. Entries that bring something to the table are marked as "favored",
   at least until the next run. The rest is deprioritized for subsequent
   fuzzing rounds. */

static void cull_queue(void) {

  struct queue_entry* q;
  u8 temp_v[MAP_SIZE];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE);

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* For every bit of the bitmap, see if the temp_v[] is still in its
     virgin state. If yes, and if it has a top_rated[] contender,
     mark that entry as favored and register all its trace_bits[] in
     temp_v[]. If no, tough luck. */

  for (i = 0; i < (MAP_SIZE << 3); i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE;

      while (j--) temp_v[j] &= ~top_rated[i]->trace_bits[j];

      if (!top_rated[i]->favored) {

        top_rated[i]->favored = 1;
        queued_favored++;

        if (!top_rated[i]->was_fuzzed) pending_favored++;

      }

    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }

}


/* Configure shared memory and virgin_bits. This is called at startup. */

static void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_hang, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode)
    setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}


/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(void) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* Auto-detect resumption attempts. */

  fn = alloc_printf("%s/queue", in_dir);
  if (!access(fn, F_OK)) in_dir = fn; else ck_free(fn);

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);

  }

  for (i = 0; i < nl_cnt; i++) {

    struct stat st;

    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8  passed_det = 0;

    free(nl[i]); /* not tracked */
 
    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      ck_free(dfn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    if (!st.st_size) 
      FATAL("Test case '%s' has zero length", fn);

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);

  }

  free(nl); /* not tracked */

  if (!queued_paths) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);

  }

  last_path_time = 0;
  queued_at_start = queued_paths;

}


/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

static void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    close(dev_null_fd);

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "allocator_may_return_null=1", 0);

    execvp(argv[0], argv);

    /* Use a distinctive return value to tell the parent about execvp()
       falling through. This is hackish, but meh... */

    exit(EXEC_FAIL);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, WUNTRACED) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    SAYF("\n" cLRD "[-] " cRST
         "Whoops, the fork server died before doing anything useful! There are\n"
         "    several possible causes of this:\n\n"

         "    - The current memory limit (%s) is too low for this program, causing\n"
         "      it to die due to OOM very early on (e.g., in the dynamic linker). You can\n"
         "      try bumping the limit up with the -m setting in the command line. To\n"
         "      confirm this diagnosis, it may be helpful to try:\n\n"

         "      ( ulimit -Sv $[%llu << 20]; /path/to/fuzzed_app )\n\n"

         "      For binaries compiled with ASAN, please see notes_for_asan.txt.\n\n"

         "    - The binary always crashes when executed for some intrinsic reason beyond\n"
         "      our control. If so, you probably need to fix the underlying problem or\n"
         "      find a more suitable replacement.\n\n"

         "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx>.\n", DMS(mem_limit << 20), mem_limit);

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }


  if (WEXITSTATUS(status) == EXEC_FAIL)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  SAYF("\n" cLRD "[-] " cRST
       "Hmm, looks like the target binary terminated before we could establish a\n"
       "    connection to the fork server. There are three possible explanations:\n\n"

       "    - The binary is not instrumented. The fuzzer depends on compile-time\n"
       "      instrumentation to find interesting test cases. For more info on this,\n"
       "      and for instructions on how to instrument binaries, please consult the\n"
       "      README.\n\n"

       "      (In some cases, you may want to use afl-fuzz as a traditional, \"dumb\"\n"
       "      fuzzer. If that's the intent, specify the -n option - but expect it to\n"
       "      perform much worse than with the instrumentation in place).\n\n"

       "    - The current memory limit (%s) is too low for this program, causing it\n"
       "      to die due to OOM very early on (e.g., in the dynamic linker). You can\n"
       "      try bumping the limit up with the -m setting in the command line. A simple\n"
       "      way to confirm this problem may be:\n\n"

       "      ( ulimit -Sv $[%llu << 20]; /path/to/fuzzed_app )\n\n"

       "      For binaries compiled with ASAN, please see notes_for_asan.txt.\n\n"

       "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
       "      fail, poke <lcamtuf@coredump.cx>.\n", DMS(mem_limit << 20), mem_limit);

  FATAL("No instrumentation detected or fork server fault");

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char** argv) {

  static struct itimerval it;
  int status;

  child_timed_out = 0;

  memset(trace_bits, 0, MAP_SIZE);

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie. */

  if (dumb_mode) {

    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {

        dup2(dev_null_fd, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);

      }

      close(dev_null_fd);

      execvp(argv[0], argv);

      /* Use a distinctive return value to tell the parent about execvp()
         falling through. */

      exit(EXEC_FAIL);

    }

  } else {

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if (!forksrv_pid) init_forkserver(argv);

    if (write(fsrv_ctl_fd, &status, 4) != 4) {
      if (stop_soon) return 0;
      PFATAL("Unable to request new process from fork server");
    }

    if (read(fsrv_st_fd, &child_pid, 4) != 4) {
      if (stop_soon) return 0;
      PFATAL("Unable to request new process from fork server");
    }

    if (child_pid <= 0) PFATAL("Fork server is misbehaving, sorry");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode) {

    if (waitpid(child_pid, &status, WUNTRACED) <= 0) PFATAL("waitpid() failed");

  } else {

    if (read(fsrv_st_fd, &status, 4) != 4) {

      if (stop_soon) return 0;
      PFATAL("Unable to communicate with fork server");

    }

  }

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  classify_counts(trace_bits);

  total_execs++;

  /* Report outcome to caller. */

  if (child_timed_out) return FAULT_HANG;

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

  if (WEXITSTATUS(status) == EXEC_FAIL) return FAULT_ERROR;

  return FAULT_NONE;

}


/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (write(fd, mem, len) != len) 
    PFATAL("Short write to output file");

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len) {

  s32 fd = out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (skip_at && write(fd, mem, skip_at) != skip_at) 
    PFATAL("Short write to output file");

  if (tail_len && write(fd, mem + skip_at + skip_len, tail_len) != tail_len) 
    PFATAL("Short write to output file");

  if (!out_file) {

    if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 already_ran) {

  u8  fault, new_bits = 0, var_detected = 0;
  u32 i, cksum, cal_cycles = CAL_CYCLES, old_tmout = exec_tmout;
  u64 start_us, stop_us;

  /* Be a bit more generous about timeouts at this point; otherwise, when
     resuming fuzzing jobs where some test cases just barely sneaked under
     the limit, we'd see intermittent hard errors when processing the input
     dir. */

  if (timeout_given)
    exec_tmout = exec_tmout * CAL_TMOUT_PERC / 100;

  write_to_testcase(use_mem, q->len);

  start_us = get_cur_time_us();

  /* Initial run... */

  fault = run_target(argv);

  if (stop_soon || fault) goto abort_calibration;

  /* Except for running in dumb mode, we expect some data in trace_bits[].
     We also call has_new_bits() to update our map and see if this test case
     does anything new. */

  if (!dumb_mode) {

    u8 hnb;

    if (!count_bits(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    hnb = has_new_bits(virgin_bits);

    /* If we have already ran this test case, has_new_bits() is not expected
       to return a non-zero value. */

    if (hnb && already_ran) {
      var_detected = 1;
      cal_cycles   = CAL_CYCLES_LONG;
    }

    if (hnb > new_bits) new_bits = hnb;

  }

  cksum = hash32(trace_bits, MAP_SIZE, 0xa5b35705);

  /* Additional runs to detect variable paths and better estimate
     execution speed. We simply compare hashes of trace_bits[]. */

  for (i = 1; i < cal_cycles; i++) {

    u32 new_cksum;

    if (!out_file) lseek(out_fd, 0, SEEK_SET);

    fault = run_target(argv);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault) goto abort_calibration;

    new_cksum = hash32(trace_bits, MAP_SIZE, 0xa5b35705);

    if (cksum != new_cksum) {

      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      var_detected = 1;
      cal_cycles   = CAL_CYCLES_LONG;

    }

  }

  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += cal_cycles;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us = (stop_us - start_us) / cal_cycles;

  q->bitmap_size = count_bits(trace_bits);
  q->handicap    = handicap;
  q->cal_done    = 1;

  update_bitmap_score(q);

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && !already_ran && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths in a reasonably clear way. */

  if (var_detected && !q->var_behavior) {

    q->var_behavior = 1;
    queued_variable++;

    if (!strstr(q->fname, ",+var")) {

      u8* new_fn = alloc_printf("%s,+var", q->fname);

      if (rename(q->fname, new_fn))
        PFATAL("Unable to rename '%s'", q->fname);

      ck_free(q->fname);
      q->fname = new_fn;

    }

  }

  exec_tmout = old_tmout;
  return fault;

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;
  u32 id = 0;

  while (q) {

    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(argv, q, use_mem, 0, 0);
    ck_free(use_mem);

    if (stop_soon) return;

    switch (res) {

      case FAULT_HANG:

        if (timeout_given) {

          FATAL("Test case '%s' results in a hang (adjusting -t may help)", fn);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

          FATAL("Test case '%s' results in a hang", fn);

        }

      case FAULT_CRASH:  

        SAYF("\n" cLRD "[-] " cRST
             "Oops, the program crashed with one of the test cases provided. There are\n"
             "    several possible explanations:\n\n"

             "    - The test case causes known crashes under normal working conditions. If\n"
             "      so, please remove it. The fuzzer should be seeded with interesting\n"
             "      inputs - but not ones that cause an outright crash.\n\n"

             "    - The current memory limit (%s) is too low for this program, causing\n"
             "      it to die due to OOM even for valid input files. To fix this, try\n"
             "      bumping it up with the -m setting in the command line. If in doubt,\n"
             "      try running something along the lines of:\n\n"

             "      ( ulimit -Sv $[%llu << 20]; /path/to/binary [...] <testcase )\n\n"

             "      For binaries compiled with ASAN, please see notes_for_asan.txt.\n\n"

             "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
             "      fail, poke <lcamtuf@coredump.cx>.\n", DMS(mem_limit << 20), mem_limit);

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:

        FATAL("Unable to execute target application ('%s')", argv[0]);

      case FAULT_NOINST:

        FATAL("No instrumentation detected");

      case FAULT_NOBITS: 

        useless_at_start++;
        WARNF("No new instrumentation output, test case may be useless.");

    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;
    id++;

  }

  OKF("All test cases processed.");

}


/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(void) {

  struct queue_entry* q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {

    u8  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) rsl = q->fname; else rsl++;

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. */

    if (!strncmp(rsl, "id:", 3) && sscanf(rsl + 3, "%06u", &orig_id) == 1 &&
        orig_id == id) {

      u8* src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {

        struct queue_entry* s = queue;
        while (src_id-- && s) s = s->next;
        if (s) q->depth = s->depth + 1;

        if (max_depth < q->depth) max_depth = q->depth;

      }

    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, rsl);

    }

    /* Pivot to the new queue entry. */

    if (link(q->fname, nfn)) PFATAL("link() failed");
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) mark_as_det_done(q);

    q = q->next;
    id++;

  }

}


/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8* describe_op(u8 hnb) {

  static u8 ret[256];

  if (syncing_party) {

    sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);

  } else {

    sprintf(ret, "src:%06u", current_entry);

    if (splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%06u", splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {

      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d", 
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);

    } else sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);

  }

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}


/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void) {

  u8* fn = alloc_printf("%s/crashes/README.txt", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0) return;

  f = fdopen(fd, "w");

  if (!f) {
    close(fd);
    return;
  }

  fprintf(f, "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n");

  fclose(f);

}


/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. */

static void save_if_interesting(void* mem, u32 len, u8 fault) {

  u8  *fn = "";
  u8  hnb;
  s32 fd;

  switch (fault) {

    case FAULT_NONE:

      /* Keep only if there are new bits in the map, add to queue for
         future fuzing, etc. */

      if (!(hnb = has_new_bits(virgin_bits))) return;

      fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                        describe_op(hnb));

      add_to_queue(fn, len, 0);

      if (hnb == 2) {
        queue_top->has_new_cov = 1;
        queued_with_cov++;
      }

      queue_top->bitmap_size = count_bits(trace_bits);
      update_bitmap_score(queue_top);      

      break;

    case FAULT_HANG:

      /* Hangs are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      total_hangs++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return;

      if (!dumb_mode) {

        simplify_trace(trace_bits);

        if (!has_new_bits(virgin_hang)) return;

      }

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

      /* This is handled in a manner roughly similar to hangs,
         except for slightly different limits. */

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return;

      if (!dumb_mode) {

        simplify_trace(trace_bits);

        if (!has_new_bits(virgin_crash)) return;

      }

      if (!unique_crashes) write_crash_readme();

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

      unique_crashes++;

      last_crash_time = get_cur_time();

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

  }

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'\n", fn);

  if (write(fd, mem, len) != len) PFATAL("Short write to '%s'", fn);

  if (fault) ck_free(fn);

  close(fd);

}


/* Update stats file for unattended monitoring. */

static void write_stats_file(void) {

  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  fprintf(f, "start_time     : %llu\n"
             "last_update    : %llu\n"
             "fuzzer_pid     : %u\n"
             "cycles_done    : %llu\n"
             "execs_done     : %llu\n"
             "paths_total    : %u\n"
             "cur_path       : %u\n"
             "pending_favs   : %u\n"
             "pending_total  : %u\n"
             "variable_paths : %u\n"
             "unique_crashes : %llu\n"
             "unique_hangs   : %llu\n",
             start_time / 1000, get_cur_time() / 1000, getpid(),
             queue_cycle - 1, total_execs, queued_paths, current_entry,
             pending_favored, pending_not_fuzzed, queued_variable,
             unique_crashes, unique_hangs);

  fclose(f);

}


/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_id_files(u8* path) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (!strncmp(d_ent->d_name, "id:", 3)) {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}


/* Another helper for cleaning up the .synced dir. */

static u8 delete_in_subdirs(u8* path) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.') {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (delete_id_files(fname)) return 1;
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}


/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void) {

  FILE* f;
  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);

  f = fopen(fn, "r");

  if (f) {

    u64 start_time, last_update;
    u32 fuzzer_pid;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n"
                  "fuzzer_pid     : %u\n", &start_time, &last_update,
                  &fuzzer_pid) != 3) FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* First of all, let's see if the other fuzzer is still running. */

    if (!kill(fuzzer_pid, 0) || errno != ESRCH) {

      SAYF("\n" cLRD "[-] " cRST
           "Looks like the job output directory is being actively used by another\n"
           "    instance of afl-fuzz, running with PID %u. You will need to choose a\n"
           "    different %s or stop the other process first.\n", fuzzer_pid,
           sync_id ? "fuzzer ID" : "output location");

       FATAL("Directory '%s' is in use", out_dir);

    }

    /* With this out of the way, let's see how much work is at stake. */

    if (last_update - start_time > 60 * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than an hour's worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"
  
           "    Please remove or rename the directory manually, or choose a different\n"
           "    output location for this job.\n");

       FATAL("At-risk data found in in '%s'", out_dir);

    }

  }

  ck_free(fn);

  OKF("Output directory exists but deemed OK to reuse.");
  ACTF("Deleting old session data...");

  // Okay, let's get the ball rolling! First, we need to get rid of the entries
  // in <out_dir>/.synced/*/id:*, if any are present.

  fn = alloc_printf("%s/.synced", out_dir);
  if (delete_in_subdirs(fn)) goto dir_cleanup_failed;
  ck_free(fn);

  // Next, we need to clean up <out_dir>/queue/.state/ subdirectories:

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_id_files(fn)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_paths", out_dir);
  if (delete_id_files(fn)) goto dir_cleanup_failed;
  ck_free(fn);

  // Then, get rid of the .state subdirectory itself (should be empty by now)
  // and everything matching <out_dir>/queue/id:*.

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_id_files(fn)) goto dir_cleanup_failed;
  ck_free(fn);

  // All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:* next:

  fn = alloc_printf("%s/crashes", out_dir);
  if (delete_id_files(fn)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/hangs", out_dir);
  if (delete_id_files(fn)) goto dir_cleanup_failed;
  ck_free(fn);

  // And now, for some finishing touches:

  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzzer_stats", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  // Wow... is that all? If yes, celebrate!

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tied to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n", fn);

  FATAL("Output directory cleanup failed");

}



/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void) {

  u32 banner_len, banner_pad;
  u8 tmp[256]; 

  /* Compute some mildly useful bitmap stats. */

  u32 t_bytes = count_non_255_bytes(virgin_bits);
  u32 t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Figure out current running time. */

  s64 cur_ms   = get_cur_time();
  s64 run_time = cur_ms - start_time;
  double avg_exec, t_byte_ratio;

  if (not_on_tty) return;

  if (!run_time) run_time = 1;

  /* Calculate average exec speed and adjust UI update frequency. */

  avg_exec = ((double)total_execs) * 1000 / run_time;

  stats_update_freq = avg_exec / UI_TARGET_HZ;

  if (!stats_update_freq) stats_update_freq = 1;

  if (clear_screen) {

    SAYF(TERM_CLEAR);
    clear_screen = 0;

  }

  SAYF(TERM_HOME);

  /* Let's start by drawing a centered banner. */

  banner_len = 22 + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;

  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, cYEL "american fuzzy lop " cLCY VERSION cLGN
          " (%s)",  use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10

  /* Lord, forgive me this. */

  SAYF(bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB bH
       bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cNOR);

  } else {

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1) strcpy(tmp, cMGN); else

    /* Subsequent cycles, but we're still making finds. */
    if (!cycles_wo_finds) strcpy(tmp, cYEL); else

    /* No finds for a long time and no test cases to try. */
    if (cycles_wo_finds > 20 && !pending_not_fuzzed) strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cNOR "%-34s " bSTG bV bSTOP
       "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1)) {

    SAYF(bV bSTOP "   last new path : " cNOR "%-34s ",
         DTD(cur_ms, last_path_time));

  } else {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cNOR 
           " (non-instrumented mode)        ");

     else

      SAYF(bV bSTOP "   last new path : " cNOR "none yet " cLRD
           "(odd, check syntax!)      ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cNOR "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
         (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cNOR "%-34s " bSTG bV bSTOP
       " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cNOR,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
         (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cNOR "%-34s " bSTG bV bSTOP 
       "   uniq hangs : " cNOR "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny becuse we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
          queue_cur->favored ? "" : "*",
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cNOR "%-17s " bSTG bV bSTOP, tmp);

  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  sprintf(tmp, "%s (%0.02f%%)", DI(t_bytes), t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : 
       ((t_bytes < 200 && !dumb_mode) ? cPIN : cNOR), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cNOR "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cNOR "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
       " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cNOR "%-21s " bSTG bV bSTOP 
       " favored paths : " cNOR "%-22s " bSTG bV "\n", stage_name, tmp);

  if (!stage_max) {

    sprintf(tmp, "n/a");

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cNOR "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cNOR "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " total execs : " cNOR "%-21s " bSTG bV bSTOP
       " total crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
       total_crashes ? cLRD : cNOR, tmp);

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cNOR "%-21s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_hangs), DI(unique_hangs),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF (bSTG bV bSTOP "   total hangs : " cNOR "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
       bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  sprintf(tmp, "%s/%s, %s/%s, %s/%s",
          DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
          DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP2]),
          DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));

  SAYF(bV bSTOP "   bit flips : " cNOR "%-37s " bSTG bV bSTOP "   levels : "
       cNOR "%-11s " bSTG bV "\n", tmp, DI(max_depth));

  sprintf(tmp, "%s/%s, %s/%s, %s/%s",
          DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
          DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
          DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cNOR "%-37s " bSTG bV bSTOP "  pending : "
       cNOR "%-11s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  sprintf(tmp, "%s/%s, %s/%s, %s/%s",
          DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
          DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
          DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cNOR "%-37s " bSTG bV bSTOP " pend fav : "
       cNOR "%-11s " bSTG bV "\n", tmp, DI(pending_favored));

  sprintf(tmp, "%s/%s, %s/%s, %s/%s",
          DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
          DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
          DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cNOR "%-37s " bSTG bV bSTOP " imported : "
       cNOR "%-11s " bSTG bV "\n", tmp, DI(queued_imported));


  sprintf(tmp, "%s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "       havoc : " cNOR "%-37s " bSTG bV bSTOP
       " variable : %s%-11s " bSTG bV "\n", tmp, queued_variable ? cLRD : cNOR,
       DI(queued_variable));

  if (!bytes_trim_out) {

    sprintf(tmp, "n/a");

  } else {

    sprintf(tmp, "%s/%s (%0.02f%% gain)", DMS(bytes_trim_in - bytes_trim_out),
            DI(trim_execs), ((double)(bytes_trim_in - bytes_trim_out)) * 100
            / bytes_trim_in);

  }

  SAYF(bV bSTOP "        trim : " cNOR "%-37s " bSTG bV bSTOP 
       "   latent : " cNOR "%-11s " bSTG bV "\n", tmp, DI(queued_later_on));

  SAYF(bLB bH30 bH20 bH2 bH bHT bH20 bH2 bH2 bRB bSTOP cRST "\n");

  /* Hallelujah! */

  fflush(0);

}


/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Nothing fancy. */

static void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = total_cal_us / total_cal_cycles;
  u32 max_len = 0;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > 10000) 
    WARNF(cLRD "The target binary is pretty slow! See perf_tips.txt for help.");

  if (!resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see perf_tips.txt for help!",
            DMS(max_len));
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see perf_tips.txt for advice.",
            DMS(max_len));

    if (useless_at_start)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");


  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cNOR "%u favored, %u variable, %u total\n"
      cGRA "       Bitmap range : " cNOR "%u to %u bits (average: %0.02f bits)\n"
      cGRA "        Exec timing : " cNOR "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits, 
      ((double)total_bitmap_size) / total_bitmap_entries,
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, plus 50 ms. */

    exec_tmout = 50 + MAX(avg_us * 5 / 1000, max_us / 1000);
    exec_tmout = exec_tmout / 50 * 50;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         exec_tmout);

    timeout_given = 1;

  }

  OKF("All set and ready to roll!");

}


/* Find first power of two greater or equal to val. */

static u32 next_p2(u32 val) {

  u32 ret = 1;
  while (val > ret) ret <<= 1;
  return ret;

} 


/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

static u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf) {

  static u8 tmp[64];

  u8  fault;
  u32 cksum;
  u8  needs_write = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  if (q->len < 5) return 0;

  stage_name = tmp;

  bytes_trim_in += q->len;

  write_to_testcase(in_buf, q->len);
  fault = run_target(argv);
  trim_execs++;

  if (stop_soon || fault) goto abort_trimming;

  cksum = hash32(trace_bits, MAP_SIZE, 0xa5b35705);

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_p2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

    stage_cur = 0;
    stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 new_cksum;

      write_with_gap(in_buf, q->len, remove_pos, trim_avail);

      fault = run_target(argv);
      trim_execs++;

      if (stop_soon || fault == EXEC_FAIL) goto abort_trimming;

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

      new_cksum = hash32(trace_bits, MAP_SIZE, 0xa5b35705);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (new_cksum == cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2  = next_p2(q->len);

        memcpy(in_buf + remove_pos, in_buf + remove_pos + trim_avail, 
               move_tail);

        needs_write = 1;

      } else remove_pos += remove_len;

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % stats_update_freq)) show_stats();

      stage_cur++;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname); /* Ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    if (write(fd, in_buf, q->len) != q->len)
      PFATAL("Short write to '%s'", q->fname);

    close(fd);

  }

  fault = 0;

abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}


/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

static u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  write_to_testcase(out_buf, len);

  fault = run_target(argv);

  if (stop_soon) return 1;

  if (fault == FAULT_HANG) {

    if (subseq_hangs++ > HANG_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else subseq_hangs = 0;

  /* This handles FAULT_ERROR for us: */

  save_if_interesting(out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}


/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;

  switch (UR(3)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: min_value = HAVOC_BLK_MEDIUM;
             max_value = HAVOC_BLK_LARGE;


  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

}


/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). */

static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multipler from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 6:   perf_score *= 2; break;
    case 7 ... 12:  perf_score *= 4; break;
    case 13 ... 24: perf_score *= 6; break;
    default:        perf_score *= 8;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;

}


/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfuly, 1 if
   skipped or bailed out. */

static u8 fuzz_one(char** argv) {

  s32 len, fd, temp_len;
  s32 i, j;

  u8  *in_buf, *out_buf, *orig_in;

  u64 havoc_queued;
  u64 orig_hit_cnt, new_hit_cnt;

  u32 splice_cycle = 0;
  u32 perf_score = 100;

  u8  ret_val = 1;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't already calibrated
     in perform_dry_run(), which is called only for the initial -i data. */

  if (!queue_cur->cal_done) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often. */

    if (!queue_cur->favored && UR(100) < SKIP_NFAV_PROB) return 1;

  }

#endif /* ^IGNORE_FINDS */

  if (not_on_tty)
    ACTF("Fuzzing test case #%u (%u total)...", current_entry, queued_paths);

  /* Map the test case into memory. */

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (mmap == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_alloc(len);

  subseq_hangs = 0;

  cur_depth = queue_cur->depth;

  /***************
   * CALIBRATION *
   ***************/

  if (!queue_cur->cal_done) {

    u8 res;

    /* This is a bit half-hearted... */

    stage_name  = "calibration";
    stage_cur   = 0;
    stage_max   = CAL_CYCLES;

    show_stats();

    res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 1);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon || res != FAULT_NONE) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

  }

  /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

    len = queue_cur->len;
    queue_cur->trim_done = 1;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  perf_score = calculate_score(queue_cur);

  /* We want to skip deterministic stages if -d is given; if we have done
     any fuzzing on this case ourselves (was_fuzzed); or if it came marked
     as such from an earlier fuzzing run (!was_fuzzed but passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /******************
   * SIMPLE BITFLIP *
   ******************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_name  = "bitflip 1/1";
  stage_short = "flip1";
  stage_max   = len << 3;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  /* Two walking bits. */

  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  /* Four walking bits. */

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    out_buf[stage_cur] ^= 0xFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      stage_cur_val = j;
      out_buf[i] += j;

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      stage_cur_val = -j;
      out_buf[i] -= 2 * j;

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      out_buf[i] += j;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks). */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xffff) + j > 0xffff) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig & 0xffff) < j) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;
 
      if ((SWAP32(orig) & 0xffff) + j > 0xffff) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((SWAP32(orig) & 0xffff) < j) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name  = "interest 8/8";
  stage_short = "int8";
  stage_cur   = 0;
  stage_max   = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      if (interesting_8[j] == orig) {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  /* Setting 16-bit integers, both endians. */

  if (len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      if (interesting_16[j] != orig) {

        stage_val_type = STAGE_VAL_LE;

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if (SWAP16(interesting_16[j]) != interesting_16[j] && 
          SWAP16(interesting_16[j]) != orig) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u16*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      stage_cur_val = interesting_32[j];

      if (interesting_32[j] != orig) {

        stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if (SWAP32(interesting_32[j]) != interesting_32[j] && 
          SWAP32(interesting_32[j]) != orig) {

        stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u32*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = HAVOC_CYCLES * perf_score / 100;

  } else {

    static u8 tmp[32];
    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / 100;

  }

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << UR(HAVOC_STACK_POW2 + 1);

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {

      switch (UR(15)) {

        case 0:

          /* Flip a single bit. */

          FLIP_BIT(out_buf, UR(temp_len << 3));
          break;

        case 1: 

          /* Set byte to interesting value. */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;

        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(temp_len - 1);

            del_from = UR(temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

        case 13:

          if (temp_len + HAVOC_BLK_LARGE < MAX_FILE) {

            /* Clone bytes or insert a block of constant bytes. */

            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            clone_len  = choose_block_len(temp_len);

            clone_from = UR(temp_len - clone_len + 1);
            clone_to   = UR(temp_len);

            new_buf = ck_alloc(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (UR(4))
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to, UR(256), clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

          }

          break;

        case 14: {

            /* Overwrite bytes with a randomly selected chunk or fixed bytes. */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to, UR(256), copy_len);

            break;

          }

      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 1000) { target = target->next_1k; tid -= 1000; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc(target->len);

    if (read(fd, new_buf, target->len) != target->len)
      PFATAL("Short read from '%s'", target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;

  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!stop_soon && queue_cur->cal_done && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;
    pending_not_fuzzed--;
    if (queue_cur->favored) pending_favored--;
  }

  munmap(orig_in, queue_cur->len);

  if (in_buf != orig_in) ck_free(in_buf);
  ck_free(out_buf);

  return ret_val;

#undef FLIP_BIT

}


/* Grab interesting test cases from other fuzzers. */

static void sync_fuzzers(char** argv) {

  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;
  u32 orig_queued = queued_paths;

  sd = opendir(sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */

  while ((sd_ent = readdir(sd))) {

    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) 
      lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */    

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    show_stats();

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not. */

    while ((qd_ent = readdir(qd))) {

      u8* path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, "id:%06u", &syncing_case) != 1 || 
          syncing_case < min_accept) continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (syncing_case >= next_min_accept)
        next_min_accept = syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      fd = open(path, O_RDONLY);
      if (fd < 0) PFATAL("Unable to open '%s'", path);

      if (fstat(fd, &st)) PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(mem, st.st_size);

        fault = run_target(argv);

        if (stop_soon) return;

        syncing_party = sd_ent->d_name;
        save_if_interesting(mem, st.st_size, fault);
        syncing_party = 0;

        munmap(mem, st.st_size);

      }

      ck_free(path);
      close(fd);

    }

    if (write(id_fd, &next_min_accept, sizeof(u32)) != sizeof(u32))
      PFATAL("Short write to '%s'", qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
    
  }  

  closedir(sd);

  queued_imported += queued_paths - orig_queued;

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);

}


/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  child_timed_out = 1; 

  if (child_pid > 0) {

    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    kill(forksrv_pid, SIGKILL);

  }

}


/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. */

static void check_binary(u8* fname) {

  u8 *use_file = 0, *env_path = 0;
  struct stat st;

  s32 fd;
  u8 file_hdr[2];

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    use_file = ck_strdup(fname);

    if (!stat(use_file, &st) && !S_ISREG(st.st_mode) && (st.st_mode & 0111))
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
        use_file = alloc_printf("%s/%s", cur_elem, fname);
      else
        use_file = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(use_file, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0111))
        break;

      ck_free(use_file);
      use_file = 0;

    }

    if (!use_file) FATAL("Program '%s' not found or not executable", fname);

  }

  fd = open(use_file, O_RDONLY);

  if (fd >= 0 && read(fd, file_hdr, 2) == 2 && file_hdr[0] == '#' &&
      file_hdr[1] == '!') {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n" 
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n" 
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", fname);

  }

  if (fd >= 0) close(fd);

  ck_free(use_file);

}


/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8* name) {

  if (!use_banner) {

    if (sync_id) {

      use_banner = sync_id;

    } else {

      u8* trim = strrchr(name, '/');
      if (!trim) use_banner = name; else use_banner = trim + 1;

    }

  }

  if (strlen(use_banner) > 40) {

    u8* tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;

  }

}


/* Check terminal dimensions. */

static void check_terminal(void) {

  struct winsize ws;

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }

  if (ws.ws_row < 25 || ws.ws_col < 80) {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, your terminal window seems to be smaller than 80 x 25 characters.\n"
         "    That's not enough for afl-fuzz to correctly draw its fancy ANSI UI!\n\n"

         "    Depending on the terminal software you are using, you should be able to\n"
         "    resize the window by dragging its edges, or to adjust the dimensions in\n"
         "    the settings menu.\n");

    FATAL("Please resize terminal to 80x25");

  }

}



/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for captured crashes\n\n"

       "Execution control settings:\n\n"

       "  -f file       - program input file to write fuzzed data to\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n\n"
      
       "Fuzzing behavior settings:\n\n"

       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n\n"

       "Other stuff:\n\n"

       "  -T text       - show a specific text banner on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n\n"

       "For additional tips, please consult the README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT);

  exit(1);

}


/* Prepare output directories and fds. */

static void setup_dirs_fds(void) {

  u8* tmp;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
      PFATAL("Unable to create '%s'", sync_dir);

  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST) PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();

  }

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  tmp = alloc_printf("%s/queue/.state/redundant_paths/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  if (sync_id) {

    tmp = alloc_printf("%s/.synced/", out_dir);
    if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

  }

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");

}


/* Setup the output file for fuzzed data, if not using -f. */

static void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Make sure that core dumps don't go to a program. */

static void check_coredumps(void) {

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8  fchar;

  if (fd < 0) return;

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues due to an extended delay\n"
         "    between the fuzzed binary malfunctioning and this information being\n"
         "    eventually relayed to the fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as hangs, please log in as root\n" 
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    FATAL("Pipe at the beginning of 'core_pattern'");

  }

 
  close(fd);

}


/* Validate and fix up out_dir and sync_dir when using -S. */

static void fix_up_sync(void) {

  u8* x = sync_id;

  if (dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic) FATAL("-d is implied in -S / -M mode");

  while (*x) {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;

  }

  if (strlen(sync_id) > 32) FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir  = x;

  if (!force_deterministic) {
    skip_deterministic = 1;
    use_splicing = 1;
  }

}


/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {
  clear_screen = 1;
}


/* Check ASAN options. */

static void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS");

  if (x && !strstr(x, "abort_on_error=1"))
    FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

} 


/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " (" __DATE__ " " __TIME__ 
       ") by <lcamtuf@google.com>\n");

  signal(SIGHUP,   handle_stop_sig);
  signal(SIGINT,   handle_stop_sig);
  signal(SIGTERM,  handle_stop_sig);
  signal(SIGALRM,  handle_timeout);
  signal(SIGWINCH, handle_resize);

  signal(SIGTSTP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  while ((opt = getopt(argc,argv,"+i:o:f:m:t:T:dnB:S:M:")) > 0)

    switch (opt) {

      case 'i':

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;
        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M':

        force_deterministic = 1;

      case 'S': /* sync ID */

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = optarg;
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 't':

        exec_tmout = atoi(optarg);
        if (exec_tmout < 20) FATAL("Bad or dangerously low value of -t");
        timeout_given = 1;
        break;

      case 'm': {

          u8 suffix = 'M';

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1)
            FATAL("Bad syntax used for -m");

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

      case 'd':

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B':

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and you
           want to start a new process seeded just with that case - but you
           don't want the fuzzer to re-invent new test cases for paths already
           discovered by the earlier run.

           In essence, specifying -B and using fuzz_bitmap from the earlier
           run will cause the fuzzer to consider all paths reflected in that
           map to be uninteresting, and look only for the stuff that isn't
           in that bitmap yet. */

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'n':

        dumb_mode = 1;
        break;

      case 'T':

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  check_asan_opts();

  if (sync_id) fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same!");

  fix_up_banner(argv[optind]);

  check_terminal();

  start_time = get_cur_time();

  check_coredumps();

  setup_shm();

  setup_dirs_fds();

  read_testcases();

  pivot_inputs();

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  perform_dry_run(argv + optind);

  cull_queue();

  show_init_stats();

  if (stop_soon) goto stop_fuzzing;

  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }

  clear_screen = 1;

  while (1) {

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {

      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      show_stats();

      if (not_on_tty) 
        ACTF("Entering queue cycle %llu.", queue_cycle);

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing) cycles_wo_finds++; else use_splicing = 1;

      } else cycles_wo_finds = 0;

      prev_queued = queued_paths;

    }

    skipped_fuzz = fuzz_one(argv + optind);

    write_stats_file();

    if (stop_soon) break;

    if (sync_id && !skipped_fuzz) {
      
      if (!(sync_interval_cnt++ % SYNC_INTERVAL))
        sync_fuzzers(argv + optind);

    }

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    current_entry++;

  }

  if (queue_cur) show_stats();

stop_fuzzing:

  SAYF(cLRD "\n+++ Testing aborted by user +++\n" cRST);

  destroy_queue();
  alloc_report();

  OKF("We're done here. Have a nice day!");

  exit(0);

}
