#!/usr/bin/env python3
# coding=utf-8
# Quick And Dirty disassembler - used for testing
# (C) Athanasios Kostopoulos 2021

import sys
import binaryninja

if len(sys.argv) != 2:
    print("Usage: qnd.py Amiga_file")
    sys.exit(1)

fname = sys.argv[1]
bv = binaryninja.BinaryViewType.get_view_of_file(fname)
bv.update_analysis_and_wait()
lines = bv.get_linear_disassembly()
for line in lines:
    print(line)
