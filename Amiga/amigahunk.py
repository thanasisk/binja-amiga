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

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryReader, BinaryView
from binaryninja.enums import (SectionSemantics, SegmentFlag, SymbolType)
from binaryninja.types import Symbol
from .constants import RAM_SEGMENTS, special_registers, hunk_types
from .fsm import AmigaHunkFSM

B_LONG = 4
B_WORD = 2

class HunkParseError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class AmigaHunk(BinaryView):
    name = 'AmigaHunk'
    long_name = 'Amiga 500 Hunk format'

    def __read_name(self, data):
        num_longs = self.__read_long(data)
        if num_longs == 0:
            return 0, ""
        else:
            return self.__read_name_size(data, num_longs)

    def __read_name_size(self, data, num_longs):
        size = (num_longs & 0xFFFFFF) * B_LONG
        raw_name = data.read(0, size)
        if len(raw_name) < size:
            return -1, None
        endpos = raw_name.find(b"\x00")
        if endpos == -1: # not found
            return size, raw_name
        elif endpos == 0:
            return 0, ""
        else:
            return size, raw_name[:endpos]

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['M68000'].standalone_platform
        self.data = data
        self.custom_symbols = []
        self.base_addr = 0x010000
        self.br = BinaryReader(data)
        # add memory mappings
        for address, length, comment in RAM_SEGMENTS:
            # self.add_auto_segment(address, length, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
            self.add_auto_section(comment, address, length)
        if self.is_valid_for_data(self.data):
            self.create_segments()
            self.add_special_registers()
            #self.find_copper_lists()

    def add_special_registers(self):
        _type = self.parse_type_string("uint32_t")[0]
        for addr in special_registers.keys():
            self.define_user_data_var(addr, _type)
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, special_registers[addr]))

    def create_segments(self):
        self.br.seek(0x08)
        hunktypes = []
        numhunks = self.br.read32be()
        first_hunk = self.br.read32be()
        last_hunk = self.br.read32be()
        self.br.seek_relative(0x04)
        print(len(self.data),numhunks, first_hunk, last_hunk)
        for i in range(0, numhunks):
            hunktypes.append(self.br.read32be())
            if hunktypes[i] == hunk_types['HUNK_CODE']:
                print("code hunk found! 0x%X" % self.br.offset)
                num_words = self.br.read32be()
                code_sz = num_words * B_LONG
                print("Length of code: %d" %code_sz )
                self.add_auto_segment( self.base_addr, code_sz, self.br.offset, code_sz, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
                self.add_user_section("CodeHunk_"+str(i), self.base_addr, code_sz, SectionSemantics.ReadOnlyCodeSectionSemantics)
                self.add_function(self.base_addr,Architecture['M68000'].standalone_platform)
                print(self.get_functions_at(self.base_addr))
                self.br.seek_relative(code_sz)
            elif hunktypes[i] == hunk_types['HUNK_DATA']:
                print("data hunk found! 0x%X" % self.br.offset)
                num_words = self.br.read32be()
                data_sz = num_words * B_LONG
                print("Length of data: %d" %data_sz )
                # segment? base addr?
                self.add_user_section("DataHunk_"+str(i), self.base_addr, data_sz, SectionSemantics.ReadOnlyDataSectionSemantics)
                self.br.seek_relative(data_sz)
            elif hunktypes[i] == hunk_types['HUNK_DEBUG']:
                debug_sz = self.br.read32be()
                print("DEBUG",str(i),str(debug_sz))
                idx += debug_sz
                """
                while True:
                    s, n = self.__read_name(self.data)
                    if s == 0:
                        break
                    off = self.__read_long(self.data)
                    self.custom_symbols.append((n, off))
                    print(self.custom_symbols)
                """
            elif hunktypes[i] == hunk_types['HUNK_UNIT']:
                unit_sz = self.br.read32be() * B_LONG
                print("UNIT",str(i),str(unit_sz))
                #idx += unit_sz
                candidate = self.br.read32be()
                print("%X" % candidate)
            elif hunktypes[i] == hunk_types['HUNK_BSS']:
                bss_sz = self.br.read32be() * B_LONG
                print("BSS", str(i), str(bss_sz))
                self.br.seek_relative(bss_sz)
            elif hunktypes[i] == hunk_types['HUNK_NAME']:
                name_sz = self.br.read32be() * B_LONG
                print("NAME", str(i), str(name_sz))
                self.br.seek_relative(name_sz)
            elif hunktypes[i] == hunk_types['HUNK_EXT']:
                idx = self.br.offset
                offset = self.find_next_data(idx, "\x00\x00\x00\x00")
                if offset is not None:
                    offset -= idx
                    print("HUNK_EXT",str(offset))
                    self.br.seek_relative(offset)
            elif hunktypes[i] == hunk_types['HUNK_END']:
                idx = self.br.offset
                print("HUNK_END", str(idx))
                self.br.seek_relative(0x04)
            elif hunktypes[i] == hunk_types['HUNK_SYMBOL']:
                idx = self.br.offset
                offset = self.find_next_data(idx, "\x00\x00\x00\x00") 
                if offset is not None:
                    offset -= idx
                    print("HUNK_SYMBOL", str(offset))
                    self.br.seek_relative(offset)
            else:
                print("Unsupported hunk type: %.4X at offset: 0x%.8X" % (hunktypes[i], self.br.offset))
                if hunktypes[i] in hunk_types.keys():
                    print(hunk_types[hunktypes[i]])

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,2)
        return header[0:2] in [b"\x00\x00", b"\xf3\x03"]

    def perform_is_executable(self):
        header = self.data.read(0,8)
        strings = header[4:8]
        if strings != 0x00:
            return False
        return header[0:2] in [b"\x00\x00", b"\xf3\x03"]