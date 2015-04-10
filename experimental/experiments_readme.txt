Here's a quick overview of the stuff you can find in this directory:

  - asan_cgroups         - a contributed script to simplify fuzzing ASAN
                           binaries with robust memory limits on Linux.

  - bash_harness         - a simple shell harness used to find a bunch of
                           post-Shellshock bugs.

  - canvas_harness       - a test harness used to find browser bugs with a 
                           corpus generated using simple image parsing 
                           binaries & afl-fuzz.

  - clang_asm_normalize  - a script that makes it easy to instrument
                           hand-written assembly, provided that you have clang.

  - crash_triage         - a very rudimentary example of how to annotate crashes
                           with additional gdb metadata.

  - distributed_fuzzing  - a sample script for synchronizing fuzzer instances
                           across multiple machines (see parallel_fuzzing.txt).

  - instrumented_cmp     - an experiment showing how a custom memcmp() or
                           strcmp() can be used to work around one of the
                           limitations of afl-fuzz.

  - libpng_no_checksum   - a sample patch for removing CRC checks in libpng.

  - post_library         - an example of how to build postprocessors for AFL.

Note that the minimize_corpus.sh tool has graduated from the experimental/
directory and is now available as ../afl-cmin. The LLVM mode has likewise
graduated to ../llvm_mode/*.

Most of the tools in this directory are meant chiefly as examples that need to
be tweaked for your specific needs. They come with some basic documentation,
but are not necessarily production-grade.
