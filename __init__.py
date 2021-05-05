# coding=utf-8
"""
Copyright (c) 2021 Athanasios Kostopoulos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""

from __future__ import print_function

import struct
#import traceback
#import os

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.plugin import PluginCommand
from binaryninja.enums import (SectionSemantics, SegmentFlag)

class AmigaHunk(BinaryView):
    name = 'Amiga500'
    long_name = 'Amiga 500 Hunk format'
    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['M68000'].standalone_platform
        self.data = data
        self.create_segments()

    def create_segments(self):
        idx = 0x08
        hunktypes = []
        numhunks = struct.unpack(">L",self.data.read(idx,4))[0]
        idx += 4
        first_hunk = struct.unpack(">L",self.data.read(idx,4))[0]
        idx += 4
        last_hunk = struct.unpack(">L",self.data.read(idx,4))[0]
        idx += 8 # skip a step
        print(len(self.data),numhunks, first_hunk, last_hunk)
        for i in range(0, numhunks):
            hunktypes.append(struct.unpack(">L",self.data.read(idx,4))[0])
            idx += 4
            print("type of %d hunk = 0x%X"% (i, hunktypes[i]))
            if hunktypes[i] == 0x03E9:
                print("code hunk found! 0x%X" % idx)
                code_sz = struct.unpack(">L",self.data.read(idx,4))[0]
                print("Length of code: %d" %code_sz )
                # TODO: fix/identify base address
                self.add_auto_segment( 0x040000, code_sz * 4, idx + 4, code_sz * 4, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
                self.add_user_section("CodeHunk_"+str(i), 0x040000, code_sz * 4, SectionSemantics.ReadOnlyCodeSectionSemantics)
    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,8)
        strings = struct.unpack(">L",header[4:8])[0]
        # strings should be 0 for loadable files
        if strings != 0x00:
            return False
        return header[0:2] in [b"\x00\x00", b"\xf3\x03"];

    def perform_is_executable(self):
        return True

AmigaHunk.register()
