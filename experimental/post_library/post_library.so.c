/*

   Postprocessor libraries can be passed to afl-fuzz to perform final cleanup of
   any mutated test cases - for example, to fix up checksums in PNG files.

   Please heed the following warnings:

   1) In almost all cases, it is more productive to comment out checksum logic
      in the targeted binary (as shown in ../libpng_no_checksum/). One possible
      exception is the process of fuzzing binary-only software in QEMU mode.

   2) Uses of postprocessors for anything other than checksums are questionable
      and may cause more harm than good. AFL is normally pretty good about
      dealing with length fields, magic values, etc.

   3) Post-processors that do anything non-trivial must be extremely robust to
      gracefully handle malformed data - otherwise, they will crash and take
      afl-fuzz down with them.

   In other words, *** THIS IS PROBABLY NOT WHAT YOU WANT *** unless you really,
   really know what you're doing.

   With that out of the way: the postprocessor library is passed to afl-fuzz via
   AFL_POST_LIBRARY. The library must be compiled with:

     gcc -shared -Wall -O3 post_library.so.c -o post_library.so

   AFL will call the afl_postprocess() function for every mutated output buffer.
   From there, you have three choices:

   1) If you don't want to modify the test case, simply return the original
      buffer pointer ('in_buf').

   2) If you want to skip this test case altogether, return NULL. Use this
      sparingly.

   3) If you want to modify the test case, allocate an appropriately-sized
      buffer, move the data into that buffer, make the necessary changes, and
      then return the new pointer. You can update *len if necessary, too.

      Note that the buffer will *not* be freed for you. To avoid memory leaks,
      you need to free it or reuse it on subsequent calls (as shown below).

      *** DO NOT MODIFY THE ORIGINAL 'in_buf' BUFFER INSTEAD. ***

    Aight. The example below shows a simple postprocessor that tries to make
    sure that all input files start with "GIF89a".

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Header that must be present at the beginning of every test case: */

#define HEADER "GIF89a"


/* The actual postprocessor routine called by afl-fuzz: */

const unsigned char* afl_postprocess(const unsigned char* in_buf,
                                     unsigned int* len) {

  static unsigned char* tmp;

  /* Skip execution altogether for buffers shorter than 6 bytes. */

  if (*len < strlen(HEADER)) return NULL;

  /* Do nothing for buffers that already start with the expected header. */

  if (!memcmp(in_buf, HEADER, strlen(HEADER))) return in_buf;

  /* Allocate memory for new buffer, reusing previous allocation if possible. */

  tmp = realloc(tmp, *len);

  /* If we're out of memory, the most graceful thing to do is to return the
     original buffer and give up on modifying it. */

  if (!tmp) return in_buf;

  /* Copy the original data to the new location. */

  memcpy(tmp, in_buf, *len);

  /* Insert the new header. */

  memcpy(tmp, HEADER, strlen(HEADER));

  /* Return modified buffer. No need to update *len in this particular case,
     as we're not changing it. */

  return tmp;

}
