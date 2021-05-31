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

    def __init__(self, data) -> None:
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['M68000'].standalone_platform
        self.data :BinaryView = data
        self.custom_symbols :list = []
        self.base_addr :int = 0x010000
        self.br = BinaryReader(self.data)
        self.is_library :bool = False
        self.is_loadseg :bool = False
        # add memory mappings
        for address, length, comment in RAM_SEGMENTS:
            self.add_auto_section(comment, address, length)
        self.add_special_registers()
            #self.find_copper_lists()

    def add_special_registers(self) -> None:
        _type = self.parse_type_string("uint32_t")[0]
        for addr in SPECIAL_REGISTERS.keys():
            self.define_user_data_var(addr, _type)
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, SPECIAL_REGISTERS[addr]))

    def __read_string(self) -> str:
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
    def parse_hunk_reloc16(self)->None:
        binaryninja.log_info("λ - reloc16 hunk found: 0x%.8X" % self.br.offset)
        number_of_offsets = self.br.read16be()
        if number_of_offsets == 0:
            return # immediate end of block
        hunk_no = self.br.read16be()
        self.br.seek_relative(hunk_no * number_of_offsets)

    def parse_hunk_reloc32(self)->None:
        binaryninja.log_info("λ - reloc32 hunk found: 0x%.8X" % self.br.offset)
        number_of_offsets = self.br.read32be()
        if number_of_offsets == 0:
            return # immediate end of block
        hunk_no = self.br.read32be()
        self.br.seek_relative(hunk_no * number_of_offsets)

    def parse_hunk_bss(self)->None:
        binaryninja.log_info("λ - bss hunk found: 0x%.8X" % self.br.offset)
        bss_sz = self.br.read32be() * BYTES_LONG
        binaryninja.log_debug("BSS size: %d" % bss_sz)
        self.br.seek_relative(bss_sz) 

    def parse_hunk_end(self)->None:
        binaryninja.log_info("HUNK_END: 0x%.8X" % self.br.offset)
        self.br.seek_relative(BYTES_LONG)

    def parse_hunk_name(self)->None:
        # TODO: expand
        binaryninja.log_info("λ - name hunk found: 0x%.8X" % self.br.offset)
        name_sz = self.br.read32be() * BYTES_LONG
        self.br.seek_relative(name_sz)

    def parse_hunk_external(self):
        # TODO: expand
        """
        Each symbol data unit consists of a type byte, 
        the symbol name length (3 bytes), the symbol name itself, 
        and further data. You specify the symbol name length in long words, 
        and pad the name field to the next longword boundary with zeros. 
        """
        binaryninja.log_info("λ - external hunk found: 0x%.8X" % self.br.offset)
        idx :int = self.br.offset
        offset = self.find_next_data(idx, "\x00\x00")
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

    def parse_hunk_unit(self):
        unit_sz = self.br.read32be() * BYTES_LONG
        binaryninja.log_info("λ - unit hunk found: 0x%.8X 0x%X" %(self.br.offset,unit_sz))
        # here be dragons!!!!!
        #candidate = self.br.read32be()
        #print("%X" % candidate)
        self.br.seek_relative(unit_sz)

    def parse_hunktype(self, hunktype):
        if hunktype == HUNKTYPES['HUNK_END']:
            self.parse_hunk_end()
        elif hunktype == HUNKTYPES['HUNK_CODE']:
            self.parse_hunk_code()
        elif hunktype == HUNKTYPES['HUNK_DATA']:
            self.parse_hunk_data()
        elif hunktype == HUNKTYPES['HUNK_NAME']:
            self.parse_hunk_name()
        elif hunktype == HUNKTYPES['HUNK_BSS']:
            self.parse_hunk_bss()
        elif hunktype == HUNKTYPES['HUNK_RELOC32']:
            self.parse_hunk_reloc32()
        elif hunktype == HUNKTYPES['HUNK_RELOC16']:
            self.parse_hunk_reloc16()
        elif hunktype == HUNKTYPES['HUNK_SYMBOL']:
            self.parse_hunk_symbol()
        elif hunktype == HUNKTYPES['HUNK_DEBUG']:
            self.parse_hunk_debug()
        elif hunktype == HUNKTYPES['HUNK_UNIT']:
            self.parse_hunk_unit()
        else:
            binaryninja.log_info("unknown hunk %.4X %.8X" % (hunktype, self.br.offset))