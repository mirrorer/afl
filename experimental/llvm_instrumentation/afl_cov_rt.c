/*
   american fuzzy lop - LLVM instrumentation runtime
   -------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com>

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   *** EXPERIMENTAL VERSION ***

   Note: afl_setup.s could be just rewritten here in C.

*/

void __afl_init();

__attribute__((constructor)) void __afl_init_init() {
  __afl_init();
}
