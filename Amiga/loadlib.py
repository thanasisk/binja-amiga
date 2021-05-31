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
from .amigahunk import AmigaHunk, BYTES_LONG
from .constants import HUNKTYPES

class AmigaLoadLib(AmigaHunk):
    name = 'AmigaLoadLib'
    long_name = 'Amiga 500 Library format'

    def __init__(self, data):
        super().__init__(data)
        if self.is_valid_for_data(self.data):
            self.create_segments()

    def create_segments(self):
        self.br.seek(0x04)
        self.__get_library_hunks()
        
    @classmethod
    def is_valid_for_data(self, data)->bool:
        header :bytes = data.read(0,8)
        strings :bytes = header[4:8]
        self.is_library = header[0:4] == b'\x00\x00\x03\xE7'
        return self.is_library

    def perform_is_executable(self):
       return True

    def __get_library_hunks(self)->None:
        numhunks :int = 0
        hunktype :int = 0xDEADBEEF
        self.br.seek(0)
        while self.br.read32be() != None and not self.br.eof:
            if self.data.is_valid_offset(self.br.offset):
                hunktype = self.br.read32be()
                self.parse_hunktype(hunktype)
            else:
                self.br.seek_relative(BYTES_LONG)
                print("offset: %X: " % self.br.offset)
        return numhunks