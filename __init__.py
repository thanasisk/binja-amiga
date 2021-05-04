
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
import traceback
import os

from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.binaryview import BinaryView, BinaryReader, BinaryViewType
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import AddressField, ChoiceField, get_form_input
from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (Endianness, BranchType, InstructionTextTokenType,
        LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag,
        ImplicitRegisterExtend, SymbolType)
from binaryninja.enums import SectionSemantics

class AmigaHunk(BinaryView):
    name = 'Amiga500'
    long_name = 'Amiga 500 Hunk format'
    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['M68000'].standalone_platform
        self.data = data
        self.create_segments()

    def create_segments(self):
        idx = 0x00
        hunktypes = []
        magic = self.data.read(idx,4)
        idx += 4
        string = self.data.read(idx,4)
        idx += 4
        numhunks = struct.unpack(">L",self.data.read(idx,4))[0]
        idx += 4
        first_hunk = struct.unpack(">L",self.data.read(idx,4))[0]
        idx += 4
        last_hunk = struct.unpack(">L",self.data.read(idx,4))[0]
        idx += 8 # skip a step
        print(len(self.data),numhunks, first_hunk, last_hunk)
        for i in range(numhunks):
            hunktypes.append(struct.unpack(">L",self.data.read(idx,4))[0])
            idx += 4
            print("type of %d hunk = 0x%X"% (i, hunktypes[i]))
            if hunktypes[i] == 0x03E9:
                print("code hunk found! 0x%X" % idx)
                code_sz = struct.unpack(">L",self.data.read(idx,4))[0]
                print("Length of code: %d" %code_sz )
                self.add_auto_segment( 0x040000, code_sz * 4, idx, code_sz * 4, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,4)
        return header[0:2] in [b"\x00\x00", b"\xf3\x03"];

    def perform_is_executable(self):
        return True

    """
    def read_uchar(self,f):
        return struct.unpack("<B", f.read(1))[0]

    def read_uint16(self, f):
        return struct.unpack("<H", f.read(2))[0]

    def read_uint32(self, f):
        return struct.unpack("<I", f.read(4))[0]

    def read_string(self, f):
        num_longs = self.read_uint32(f)
        if num_longs < 1:
            return ""
        s = f.read(num_longs * 4)
        idx = s.find("\0")
        return s[:idx]

    def read_hunk_header(self, f):
        resident_library_names = []
        while 1:
            s = self.read_string(f)
            if s == "":
                break
            resident_library_names.append(s)

        table_size = self.read_uint32(f)
        first_hunk_slot = self.read_uint32(f)
        last_hunk_slot = self.read_uint32(f)

        num_hunk_sizes = last_hunk_slot - first_hunk_slot + 1
        hunk_sizes = []
        for i in range(num_hunk_sizes):
            hunk_sizes.append(self.read_uint32(f))
        return hunk_sizes

    def read_hunk_code(self, f):
        num_longwords = self.read_uint32(f)
        return f.read(num_longwords * 4)

    def create_segments(self):
        hunk_sizes = self.read_hunk_header(self.data)
        for hunk_sz in hunk_sizes:
            print(hunk_sz)
    """
AmigaHunk.register()
