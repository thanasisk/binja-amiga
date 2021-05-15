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

from .constants import hunk_types

class AmigaHunkFSM:
    
    def __init__(self) -> None:
        self.start == self.__create_start()
        self.unit == self.__create_unit()
        self.header == self.__create_header()
        """
"HUNK_NAME": 0x03E8,
"HUNK_CODE": 0x03E9,
"HUNK_DATA": 0x03EA,
"HUNK_BSS": 0x03EB,
"HUNK_RELOC32": 0x03EC,
"HUNK_RELOC16": 0x03ED,
"HUNK_RELOC8": 0x03EE,
"HUNK_EXT": 0x03EF,
"HUNK_SYMBOL": 0x03F0,
"HUNK_DEBUG": 0x03F1,
"HUNK_END": 0x03F2,
"HUNK_OVERLAY": 0x03F5,
"HUNK_BREAK": 0x03F6,
"HUNK_DREL32": 0x03F7,
"HUNK_DREL16": 0x03F8,
"HUNK_DREL8": 0x03F9,
"HUNK_LIB": 0x03FA,
"HUNK_INDEX": 0x03FB,
"HUNK_RELOC32SHORT": 0x03FC,
"HUNK_RELRELOC32": 0x03FD,
"HUNK_ABSRELOC16": 0x03FE
"""
        self.current_state = self.start


    def __create_start(self):
        return None

    def __create_unit(self):
        return None

    def __create_header(self):
        return None