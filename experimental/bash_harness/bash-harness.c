/* 

   A very rudimentary harness for fuzzing bash, by popular request.
   Relevant link:

   http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html

   Instructions:

   1) Download bash, apply optional patches as desired, compile with:

      CC=/path/to/afl-gcc ./configure
      make clean all

      Note that the harness puts the fuzzed output in $TEST_VARIABLE. With
      Florian's patch, this is no longer passed down to the parser.

   2) Create and cd to an empty directory, put this file & the recently
      compiled bash binary in there.

   3) Run these commands (substitute /path/to/afl-gcc with the correct
      location for afl-fuzz):

      CC=/path/to/afl-gcc make bash-harness

      mkdir in_dir
      echo -n '() { a() { a; }; : >b; }' >in_dir/script.txt

   4) Run the fuzzer with:

      /path/to/afl-fuzz -d -i in_dir -o out_dir ./bash-harness

      The -d parameter is advisable only if the tested shell is fairly slow
      or if you are in a hurry; will cover more ground faster, but
      less systematically.

   5) Watch for crashes in out_dir/crashes/. Also watch for any new files
      created in cwd if you're interested in non-crash RCEs (files will be
      created whenever the shell executes "foo>bar" or something like
      that). You can correlate their creation date with new entries in
      out_dir/queue/.

      You can also modify the bash binary to directly check for more subtle
      fault conditions, or use the synthesized entries in out_dir/queue/
      as a seed for other, possibly slower or more involved testing regimes.

      Expect several hours to several days to get decent coverage.

 */

char val[1024 * 16];

main() {

  read(0, val, sizeof(val) - 1);

  setenv("TEST_VARIABLE", val, 1);

  execl("./bash", "bash", "-c", ":", 0);

} 
