#!/usr/bin/env python
#
# american fuzzy lop - LLVM instrumentation wrapper for clang
# -----------------------------------------------------------
#
# Written by Laszlo Szekeres <lszekeres@google.com>
#
# Copyright 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# *** EXPERIMENTAL VERSION ***
#

LLVM_CONFIG = 'llvm-config'

import os
import sys
import subprocess

def run_llvm_config(args):
  return subprocess.check_output([LLVM_CONFIG] + args).strip()

llvm_bin_dir = run_llvm_config(['--bindir'])
clangxx = llvm_bin_dir + '/clang++'
clang = llvm_bin_dir + '/clang'
opt = llvm_bin_dir + '/opt'
llc = llvm_bin_dir + '/llc'
gas = 'as'

afl_dir = os.path.dirname(os.path.abspath(__file__))
afl_llvm_pass = os.path.join(afl_dir, 'afl_cov.so')
afl_rt = os.path.join(afl_dir, 'afl_cov_rt.o')
afl_setup = os.path.join(afl_dir, 'afl_setup.o')

def use_clang(cmdline):
  if cmdline[0].find('afl-clang++') >= 0: cmdline[0] = clangxx
  elif cmdline[0].find('afl-clang') >= 0: cmdline[0] = clang
  return cmdline

def emit_llvm(cmdline):
  c_idx = cmdline.index('-c')
  cmdline.insert(c_idx, '-emit-llvm')
  return cmdline

def get_output_name(cmdline):
  return cmdline[cmdline.index('-o') + 1]

def set_output_name(cmdline, newname):
  newcmdline = cmdline
  newcmdline[cmdline.index('-o') + 1] = newname
  return newcmdline

def run(cmd, message=None):
  if message: print '[afl-cc]', message
  print '[afl-cc]', '>', ' '.join(cmd)
  subprocess.call(cmd)

def compile(cmdline):

  cmdline = use_clang(cmdline)

  # object compilation
  if cmdline.count('-c'):
    cmdline = emit_llvm(cmdline)
    obj = os.path.splitext(get_output_name(cmdline))[0]
    cmdline = set_output_name(cmdline, obj + '.bc')
    run(cmdline, 'Compiling: ' + obj)
    run([opt, '-load', afl_llvm_pass, '-afl-coverage',
              '-o', obj + '-afl.bc', obj + '.bc'])
    run([llc, '-o', obj + '.s',      obj + '-afl.bc'])
    run([gas, '-o', obj + '.o',      obj + '.s'])

  # linking
  else:
    cmdline += [afl_rt]
    cmdline += [afl_setup]
    run(cmdline, 'Linking:')

compile(sys.argv)
