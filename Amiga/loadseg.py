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

import binaryninja
from .amigahunk import AmigaHunk
from .constants import HUNKTYPES


class AmigaLoadSeg(AmigaHunk):
    name = 'AmigaLoadSeg'
    long_name = 'Amiga 500 LoadSeg format'
    Eloadseg_magic = b"\x00\x00\x03\xf3"

    def __init__(self, data):
        super().__init__(data)
        if self.is_valid_for_data(self.data):
            self.create_segments()

    def create_segments(self):
        hunktypes = []
        numhunks = 0
        self.br.seek(0x08)
        numhunks = self.br.read32be()
        first_hunk = self.br.read32be()
        last_hunk = self.br.read32be()
        self.br.seek_relative(0x04)
        binaryninja.log_debug("%d %d %d %d" % (len(self.data),numhunks, first_hunk, last_hunk))
        for i in range(0, numhunks):
            hunktypes.append(self.br.read32be())
            if hunktypes[i] == HUNKTYPES['HUNK_CODE']:
                super().parse_hunk_code()
            elif hunktypes[i] == HUNKTYPES['HUNK_DATA']:
                self.__parse_hunk_data()
            elif hunktypes[i] == HUNKTYPES['HUNK_DEBUG']:
                self.__parse_hunk_debug()
            elif hunktypes[i] == HUNKTYPES['HUNK_UNIT']:
                self.__parse_hunk_unit()
            elif hunktypes[i] == HUNKTYPES['HUNK_BSS']:
                self.__parse_hunk_bss()
            elif hunktypes[i] == HUNKTYPES['HUNK_NAME']:
                self.__parse_hunk_name()
            elif hunktypes[i] == HUNKTYPES['HUNK_EXT']:
                self.__parse_hunk_external()
            elif hunktypes[i] == HUNKTYPES['HUNK_END']:
                self.__parse_hunk_end()
            elif hunktypes[i] == HUNKTYPES['HUNK_SYMBOL']:
                self.__parse_hunk_symbol()
            elif hunktypes[i] == HUNKTYPES['HUNK_RELOC32']:
                self.__parse_hunk_reloc32()
            elif hunktypes[i] == HUNKTYPES['HUNK_RELOC16']:
                self.__parse_hunk_reloc16()
            else:
                binaryninja.log_warn("λ - Unsupported hunk type: %.4X at offset: 0x%.8X" % (hunktypes[i], self.br.offset))
                if hunktypes[i] in HUNKTYPES.keys():
                    binaryninja.log_debug(HUNKTYPES[hunktypes[i]])

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,8)
        strings = header[4:8]
        self.is_loadseg = header[0:4] == b"\x00\x00\x03\xf3"
        if strings != b"\x00\x00\x00\x00" and self.is_loadseg == True:
            binaryninja.log_error("λ - Unsupported LOADSEG file")
            return False
        return self.is_loadseg
