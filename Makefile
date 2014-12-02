#
# american fuzzy lop - make wrapper
# ---------------------------------
#
# Written and maintained by Michal Zalewski <lcamtuf@google.com>
# 
# Copyright 2013, 2014 Google Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# 
#   http://www.apache.org/licenses/LICENSE-2.0
#

PROGNAME    = afl
VERSION     = 0.48b

BIN_PATH    = /usr/local/bin
HELPER_PATH = /usr/local/lib/afl

PROGS       = afl-gcc afl-as afl-fuzz afl-showmap

CFLAGS     += -O3 -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DVERSION=\"$(VERSION)\"

GCC48PLUS  := $(shell expr `$(CC) -dumpversion | cut -f-2 -d.` \>= 4.8)

ifeq "$(GCC48PLUS)" "1"
  CFLAGS   += -DUSE_ASAN=1
endif

ifneq "$(HOSTNAME)" "raccoon"
  CFLAGS   += -Wno-format
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: test_gcc test_x86 $(PROGS) test_build test_prev all_done

test_gcc:
	@echo "[*] Checking for an installation of GCC..."
	@$(CC) -v >.test 2>&1; grep -iq '^gcc.version' .test || ( echo; echo "Oops, looks like you don't have GCC installed (or you need to specify \$CC)."; echo; rm -f .test; exit 1 )
	@rm -f .test

test_x86: | test_gcc
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) -w -x c - -o .test || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "(If you are looking for ARM, see experimental/arm_support/README.)"; echo; exit 1 )
	@rm -f .test

afl-gcc: afl-gcc.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@
	ln -s afl-gcc afl-g++ 2>/dev/null || true

afl-as: afl-as.c afl-as.h $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@
	ln -s afl-as as  2>/dev/null || true

afl-fuzz: afl-fuzz.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@

afl-showmap: afl-showmap.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@

test_build: afl-gcc afl-as afl-showmap
	@echo "[*] Testing GCC wrapper and instrumentation output..."
	AFL_QUIET=1 AFL_PATH=. ./afl-gcc $(CFLAGS) test-instr.c -o test-instr
	echo 0 | AFL_SINK_OUTPUT=1 AFL_QUIET=1 ./afl-showmap ./test-instr 2>.test-instr0
	echo 1 | AFL_SINK_OUTPUT=1 AFL_QUIET=1 ./afl-showmap ./test-instr 2>.test-instr1
	@rm -f test-instr
	@diff -qs .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please ping <lcamtuf@google.com> to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

test_prev: test_build
	@test -f "$(HELPER_PATH)/as"; TR="$$?"; if [ "$$TR" = "0" ]; then echo "[!] NOTE: You seem to have another copy of afl installed in $(HELPER_PATH)."; echo "    You must use 'make install' or set AFL_PATH to use the current build instead."; else echo "[+] No previously-installed build detected, no need to replace anything."; fi

all_done: test_prev
	@echo "[+] All done! Be sure to review README - it's pretty short and useful."

clean:
	rm -f $(PROGS) as afl-g++ *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test
	rm -rf out_dir

install: all
	mkdir -p -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(HELPER_PATH)
	install afl-gcc afl-g++ afl-fuzz afl-showmap $${DESTDIR}$(BIN_PATH)
	install afl-as as $${DESTDIR}$(HELPER_PATH)

publish: clean
	test "`basename $$PWD`" = "afl" || exit 1
	cd ..; rm -rf $(PROGNAME)-$(VERSION); cp -pr $(PROGNAME) $(PROGNAME)-$(VERSION); \
	  tar cfvz ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz $(PROGNAME)-$(VERSION)
	chmod 644 ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz
	( cd ~/www/afl/releases/; ln -s -f $(PROGNAME)-$(VERSION).tgz $(PROGNAME)-latest.tgz )
	cat docs/README >~/www/afl/README.txt
	cat docs/status_screen.txt >~/www/afl/status_screen.txt
	cat docs/related_work.txt >~/www/afl/related_work.txt



