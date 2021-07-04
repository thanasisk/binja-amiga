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
from binaryninja.types import Symbol
from binaryninja.function import InstructionInfo, InstructionTextTokenType, InstructionTextToken
from m68k import M68000, OpImmediate

COPPER_INSTRUCTIONS = [ 'CMOVE', 'CSKIP', 'CWAIT', 'CEND' ]
CEND = 0xFFFFFFFE
#class A500(M68000):
class A500(Architecture):
    name = "A500"
    # Sizes
    SIZE_BYTE = 0
    SIZE_WORD = 1
    SIZE_LONG = 2

    # BROKEN
    def perform_get_instruction_info(self, data, addr):
        instr, length, _size, _source, dest, _third = self.decode_instruction(data)
        if instr == 'unimplemented':
            return None
        result = InstructionInfo()
        result.length = length
        if instr in COPPER_INSTRUCTIONS:
            conditional = False
            branch_dest = None
            return result
        else:
            return None
    def perform_get_instruction_low_level_il(self, data, addr, il):
        instr, length, size, source, dest, third = self.decode_instruction(data)
        if instr is not None:
            if source is not None:
                pre_il = source.get_pre_il(il)
                if pre_il is not None:
                    il.append(pre_il)
            self.generate_instruction_il(il, instr, length, size, source, dest, third)
            if source is not None:
                post_il = source.get_post_il(il)
                if post_il is not None:
                    il.append(post_il)
        else:
            il.append(il.unimplemented())
        return length
    
    def generate_instruction_il(self, il, instr, length, size, source, dest, third):
        size_bytes = None
        if size is not None:
            size_bytes = 1 << size
        if instr == 'CWAIT':
            if source is not None:
                il.append(source.get_source_il(il))
        elif instr == 'CSKIP':
            if source is not None:
                il.append(source.get_source_il(il))
        elif instr == 'CEND':
            if source is not None:
                il.append(source.get_source_il(il))
        elif instr == 'CMOVE':
            if source is not None:
                il.append(source.get_source_il(il))
        else:
            il.append(il.uninplemented())

    # BROKEN
    def perform_get_instruction_text(self, data, addr):
        instr, length, _size, source, dest, third = self.decode_instruction(data)
        #print("perform_get_instruction_text: %s" % instr)
        if instr == 'unimplemented':
            return None
        if instr in COPPER_INSTRUCTIONS:
            #if size is not None:
            #    instr += SizeSuffix[size]
            tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, "%-10s" % instr)]
            if source is not None:
                tokens += source.format(addr)
            if dest is not None:
                if source is not None:
                    tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ',')]
                tokens += dest.format(addr)
            if third is not None:
                if source is not None or dest is not None:
                    tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ',')]
                tokens += third.format(addr)
            return tokens, length
        else:
            return None, None

    # Yay, fixed!
    def decode_instruction(self, data):
        error_value = ('unimplemented', len(data), None, None, None, None)
        instr = None
        length = None
        size = None
        source = None
        dest = None
        third = None
        if len(data) < 4:
            return error_value
        instruction = struct.unpack_from('>L', data)[0]
        if instruction == CEND:
            instr = 'CEND'
            size = 4
            length = 4
            return instr, length, size, source, dest, third
        #msb = instruction >> 8
        #opcode = msb >> 4
        instr_type = instruction & 0x00010001
        if instr_type == 0x00010000:
            comment = "CWAIT"
            #comment += disassemble_wait(value)
            _source = struct.unpack_from(">H", data, 0)[0]
            src = OpImmediate(2, _source)
            instr = comment
            size = 4
            length = 4
            source = src
        elif instr_type == 0x00010001:
            comment = "CSKIP"
            instr = comment
            size = 4
            length = 4
            #mask = ((1 << 0x10) - 1) << 0x10
            #_source = instruction & 0xFFFF0000
            _source = struct.unpack_from(">H", data, 0)[0]
            src = OpImmediate(2, _source)
            source = src
            #comment += disassemble_wait(value)
        elif instr_type == 0x00000000 or instr_type == 0x00000001:
            comment = "CMOVE"
            _source = struct.unpack_from(">H", data, 0)[0]
            src = OpImmediate(2, _source)
            instr = comment
            size = 4
            length = 4
            source = src
        else:
            print("NOT RECOGNIZED")
        return instr, length, size, source, dest, third
