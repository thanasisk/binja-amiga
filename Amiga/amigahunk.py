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
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryReader, BinaryView
from binaryninja.enums import (SectionSemantics, SegmentFlag, SymbolType)
from binaryninja.types import Symbol
from .constants import RAM_SEGMENTS, SPECIAL_REGISTERS, HUNKTYPES

# stating the obvious
BYTES_LONG = 4
BYTES_WORD = 2

class HunkParseError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class AmigaHunk(BinaryView):
    name = 'AmigaHunk'
    long_name = 'Amiga 500 Hunk format'
    """
    # candidate for removal
    def __read_name(self, data): # TODO: refactor this
        num_longs = self.__read_long(data)
        if num_longs == 0:
            return 0, ""
        else:
            return self.__read_name_size(data, num_longs)

    # candidate for removal
    def __read_name_size(self, data, num_longs): # TODO refactor this
        size = (num_longs & 0x00FFFFFF) * BYTES_LONG
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
    """
    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['M68000'].standalone_platform
        self.data = data
        self.custom_symbols = []
        self.base_addr = 0x010000
        self.br = BinaryReader(data)
        self.is_library = False
        self.is_loadseg = False
        # add memory mappings
        for address, length, comment in RAM_SEGMENTS:
            self.add_auto_section(comment, address, length)
        self.add_special_registers()
            #self.find_copper_lists()

    def add_special_registers(self):
        _type = self.parse_type_string("uint32_t")[0]
        for addr in SPECIAL_REGISTERS.keys():
            self.define_user_data_var(addr, _type)
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, SPECIAL_REGISTERS[addr]))

    def create_segments(self):
        self.br.seek(0x04)
        N = self.br.read32be()
        self.br.seek_relative(N * BYTES_LONG)
        print(N)
        print(self.br.offset)
        numhunks = self.__get_library_hunks()
        
    def __get_library_hunks(self):
        hunktype = self.br.read32be()
        if hunktype == HUNKTYPES['HUNK_END']:
            return
        elif hunktype == HUNKTYPES['HUNK_CODE']:
            self.__parse_hunk_code()
        elif hunktype == HUNKTYPES['HUNK_NAME']:
            self.__parse_hunk_name()
        else:
            binaryninja.log_info("unknown hunk type")

    def __read_string(self):
        num_longs = self.br.read32be()
        if num_longs < 1:
            return ""
        s = self.br.read(num_longs * 4)
        #idx = s.find("\0")
        #return s[:idx]
        return s    
    ##
    # parsers for different hunk types 
    # 
    def parse_hunk_reloc16(self):
        binaryninja.log_info("λ - reloc16 hunk found: 0x%.8X" % self.br.offset)
        number_of_offsets = self.br.read16be()
        if number_of_offsets == 0:
            return # immediate end of block
        hunk_no = self.br.read16be()
        self.br.seek_relative(hunk_no * number_of_offsets)

    def parse_hunk_reloc32(self):
        binaryninja.log_info("λ - reloc32 hunk found: 0x%.8X" % self.br.offset)
        number_of_offsets = self.br.read32be()
        if number_of_offsets == 0:
            return # immediate end of block
        hunk_no = self.br.read32be()
        self.br.seek_relative(hunk_no * number_of_offsets)

    def parse_hunk_bss(self):
        binaryninja.log_info("λ - bss hunk found: 0x%.8X" % self.br.offset)
        bss_sz = self.br.read32be() * BYTES_LONG
        binaryninja.log_debug("BSS size: %d" % bss_sz)
        self.br.seek_relative(bss_sz) 

    def parse_hunk_end(self):
        binaryninja.log_info("HUNK_END: 0x%.8X" % self.br.offset)
        self.br.seek_relative(BYTES_LONG)

    def parse_hunk_name(self):
        binaryninja.log_info("λ - name hunk found: 0x%.8X" % self.br.offset)
        name_sz = self.br.read32be() * BYTES_LONG
        self.br.seek_relative(name_sz)

    def parse_hunk_external(self):
        binaryninja.log_info("λ - external hunk found: 0x%.8X" % self.br.offset)
        idx = self.br.offset
        offset = self.find_next_data(idx, "\x00\x00\x00\x00")
        if offset is not None:
            offset -= idx
            self.br.seek_relative(offset)

    def parse_hunk_debug(self):
        binaryninja.log_info("λ - debug hunk found 0x%.8X" % self.br.offset)
        debug_sz = self.br.read32be()
        self.br.seek_relative(debug_sz) 
      
    def parse_hunk_symbol(self):
            idx = self.br.offset
            while 1:
                symbol = self.__read_string() 
                if symbol == "":
                    break
                else:
                    print(symbol)
            """
            offset = self.find_next_data(idx, "\x00\x00\x00\x00") 
            if offset is not None:
                offset -= idx
                binaryninja.log_info("HUNK_SYMBOL 0x%.8X" % offset)
                self.br.seek_relative(offset)
            """
    def parse_hunk_data(self):
        binaryninja.log_info("λ - data hunk found! 0x%X" % self.br.offset)
        num_words = self.br.read32be()
        data_sz = num_words * BYTES_LONG
        binaryninja.log_debug("Length of data: %d" % data_sz)
        self.add_user_section("DataHunk: ", self.base_addr, data_sz, SectionSemantics.ReadOnlyDataSectionSemantics)
        self.br.seek_relative(data_sz)

    def parse_hunk_code(self):
        binaryninja.log_info("λ - code hunk found! 0x%X" % self.br.offset)
        num_words = self.br.read32be()
        code_sz = num_words * BYTES_LONG
        binaryninja.log_debug("Length of code: %d" %code_sz )
        self.add_auto_segment( self.base_addr, code_sz, self.br.offset, code_sz, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_user_section("CodeHunk:", self.base_addr, code_sz, SectionSemantics.ReadOnlyCodeSectionSemantics)
        self.add_function(self.base_addr,Architecture['M68000'].standalone_platform)
        self.br.seek_relative(code_sz)

    def __parse_hunk_unit(self):
        unit_sz = self.br.read32be() * BYTES_LONG
        binaryninja.log_info("λ - unit hunk found: 0x%.8X 0x%X" %(self.br.offset,unit_sz))
        # here be dragons!!!!!
        #candidate = self.br.read32be()
        #print("%X" % candidate)
        self.br.seek_relative(unit_sz)

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,8)
        strings = header[4:8]
        self.is_loadseg = header[0:4] == b"\x00\x00\x03\xf3"
        self.is_library = header[0:4] == b'\x00\x00\x03\xE7'
        retVal = (self.is_library or self.is_loadseg)
        if retVal == False:
            binaryninja.log_debug(header[0:4])
            binaryninja.log_error("λ - Unsupported file")
        else:
            if strings != b"\x00\x00\x00\x00" and self.is_loadseg == True:
                binaryninja.log_error("λ - Unsupported LOADSEG file")
                return False
        return retVal

    def perform_is_executable(self):
       return True

