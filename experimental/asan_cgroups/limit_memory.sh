#!/bin/sh
#
# american fuzzy lop - limit memory using cgroups
# -----------------------------------------------
#
# Written by Samir Khakimov <samir.hakim@nyu.edu> and
#            David A. Wheeler <dwheeler@ida.org>
#
# Copyright 2015 Institute for Defense Analyses.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This tool allows the amount of actual memory allocated to a program
# to be limited on Linux systems using cgroups, instead of the traditional
# setrlimit() API. This helps avoid the problems discussed in
# docs/notes_for_asan.txt.
#
# Note that this is a contributed script and its coding conventions and
# error reporting differs a bit from the ones used in tools such as afl-cmin.
#

usage() {
  echo 'Limit memory that can be used without limiting what can be allocated.'
  echo 'This is useful when fuzzing 64-bit binaries with ASAN.'
  echo 'You need to run this as root; it will run command as user USERNAME.'
  echo
  echo 'Usage:'
  printf '%s\n' " $0 [-u USERNAME] [-m MEMORY_LIMIT] [-h|--help] command..."
  echo
  echo 'Options:'
  echo '-u USERNAME : Run command as USERNAME.  It is strongly recommended'
  echo '              that you supply a username (to limit privileges).'
  echo '              Default is $USER.'
  echo '-m MEMORY_LIMIT: Limit the amount of used memory to MEMORY_LIMIT;'
  echo '              This does NOT limit the amount of allocated memory.'
  echo '              Default is 50M (50 Mebibytes)'
  echo '-h,--help:    Help'
  echo
  echo 'Example:'
  printf '%s\n' " $0 -u joe afl-fuzz -m none -i input -o output system_under_test"
  echo 'Limitations:'
  echo 'Any whitespace in 'command' is interpreted as a parameter separator,'
  echo 'due to limitations in the syntax of "su".'
}

NEW_USER=""
MEMORY_LIMIT="50M"

# Sanity checks.

if [ "$(uname -s)" != 'Linux' ] ; then
 echo "Need to be running on a Linux system" >&2
 exit 1
fi

if ! type cgcreate > /dev/null 2>&1 ; then
  echo "Need to install cgroup tools!" >&2
  if type apt-get >/dev/null 2>&1  ; then
    echo "Try: apt-get install cgroup-bin" >&2
  elif type yum >/dev/null 2>&1 ; then
    echo "Try: yum install libcgroup-tools" >&2
  fi
  usage
  exit 2
fi

# Process options.

while [ $# > 0 ] ; do
  case "$1" in
    -u)
      shift
      NEW_USER="$1"
      shift ;;
    -m)
      shift
      MEMORY_LIMIT="$1"
      shift ;;
    -h|--help)
      usage
      exit 0 ;;
    --) shift; break ;;
    -*)
      echo "Unknown option $1" >&2
      echo "Use -h for help" >&2
      exit 3 ;;
    *) break ;;
  esac
done

# Defaults
# If username unspecified, use $USER

if [ "$NEW_USER" = "" ] ; then
  NEW_USER="$USER"
fi

if ! id -u "$NEW_USER" > /dev/null 2>&1 ; then
  echo "$NEW_USER is invalid user" >&2
  exit 4
fi

# If no command provided, use "sh" as command

if [ $# = 0 ] ; then
  set sh
fi

if [ "$NEW_USER" = "root" ] ; then
  echo "Warning: executing command as root user" >&2
fi

if [ ! -d "/sys/fs/cgroup/memory/$NEW_USER" ] ; then
  cgcreate -a "$NEW_USER" -g memory:"$NEW_USER"
  if [ $? != 0 ] ; then
    echo "Could not create memory setting for user $NEW_USER" >&2
    exit 5
  fi
fi

if [ -f "/sys/fs/cgroup/memory/$NEW_USER/memory.memsw.limit_in_bytes" ] ; then
  printf '%s\n' "$MEMORY_LIMIT" > "/sys/fs/cgroup/memory/$NEW_USER/memory.memsw.limit_in_bytes"
else
  # This system does not support memsw.limit_in_bytes;
  # we must disable swapping for the memory limit to work.
  swapoff -a
  if [ $? != 0 ] ; then
    echo "Could not disable swapping." >&2
    exit 6
  fi
fi

printf '%s\n' "$MEMORY_LIMIT" > "/sys/fs/cgroup/memory/$NEW_USER/memory.limit_in_bytes"

if [ $? != 0 ] ; then
  echo "Could not set memory limit" >&2
  exit 7
fi

cgexec -g "memory:$NEW_USER" su -c "$*" "$NEW_USER"
