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

from binaryninja.plugin import PluginCommand
from .Amiga.amigahunk import AmigaHunk
from .Amiga.a500 import A500


def decode_copper_list(view, addr = None):
    if addr is None:
        addr = 0x00
    value = 0
    while(value != 0xfffffffe):
        value = struct.unpack(">L",view.read(addr, 4))[0]
        view.set_comment_at(addr,decode_copper_instruction(value))
        addr += 4

def disassemble_wait(instr):
    vp = (instr & 0xff000000) >> 24
    hp = (instr & 0x00fe0000) >> 16
    ve = (instr & 0x00007f00) >> 8
    he = (instr & 0x000000fe)
    bfd = (instr & 0x00008000) >> 15

    # bit15 can never be masked out
    v_mask = vp & (ve | 0x80)
    h_mask = hp & he
    return (" VP 0x%02x, VE 0x%02x; HP 0x%02x, HE 0x%02x; BFD %d"% ( vp, ve, hp, he, bfd))


def decode_copper_instruction(value):
    instr_type = value & 0x00010001
    print("0x%.8X 0x%.8X" % ( value, instr_type), end = ' ')
    if instr_type == 0x00010000:
        comment = "CWAIT"
        comment += disassemble_wait(value)
    elif instr_type == 0x00010001:
        comment = "CSKIP"
        comment += disassemble_wait(value)
    elif instr_type == 0x00000000 or instr_type == 0x00000001:
         comment = "CMOVE"
    else:
        comment = "Unknown Copper Instruction"
    return comment
PluginCommand.register_for_address("Decode Copperlist", "Decode CopperList", decode_copper_list)
AmigaHunk.register()
A500.register()
