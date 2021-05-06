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
from binaryninja.binaryview import BinaryView
from binaryninja.plugin import PluginCommand
from binaryninja.enums import (SectionSemantics, SegmentFlag)

from m68k import M68000
# known hunk type constants
HUNK_UNIT           = 0x03E7
HUNK_NAME 	        = 0x03E8
HUNK_CODE 	        = 0x03E9
HUNK_DATA 	        = 0x03EA
HUNK_BSS 	        = 0x03EB
HUNK_RELOC32 	    = 0x03EC
HUNK_RELOC16 	    = 0x03ED
HUNK_RELOC8 	    = 0x03EE
HUNK_EXT 	        = 0x03EF
HUNK_SYMBOL 	    = 0x03F0
HUNK_DEBUG 	        = 0x03F1
HUNK_END 	        = 0x03F2
HUNK_HEADER 	    = 0x03F3
HUNK_OVERLAY 	    = 0x03F5
HUNK_BREAK 	        = 0x03F6
HUNK_DREL32 	    = 0x03F7
HUNK_DREL16 	    = 0x03F8
HUNK_DREL8 	        = 0x03F9
HUNK_LIB 	        = 0x03FA
HUNK_INDEX 	        = 0x03FB
HUNK_RELOC32SHORT 	= 0x03FC
HUNK_RELRELOC32 	= 0x03FD
HUNK_ABSRELOC16 	= 0x03FE

class A500(M68000):
    name = "A500"
    # http://coppershade.org/articles/Code/Reference/Custom_Chip_Register_List/
    special_registers = {
        0xdff000: "BLTDDAT", #	Blitter destination early read (unusable)
        0xdff002: "DMACONR", #	DMA control (and blitter status) read
        0xdff004: "VPOSR",  #	Read vertical raster position bit 9 (and interlace odd/even frame)
        0xdff006: "VHPOSR", #	Rest of raster XY position - High byte: vertical, low byte: horizontal
        0xdff008: "DSKDATR", #	Disk data early read (unusable)
        0xdff00a: "JOY0DAT", #	Joystick/mouse 0 data
        0xdff00c: "JOT1DAT", #	Joystick/mouse 1 data
        0xdff00e: "CLXDAT", #	Poll (read and clear) sprite collision state
        0xdff010: "ADKCONR", #Audio, disk control register read
        0xdff012: "POT0DAT", #Pot counter pair 0 data
        0xdff014: "POT1DAT", #Pot counter pair 1 data
        0xdff016: "POTGOR", #Pot pin data read
        0xdff018: "SERDATR", #Serial port data and status read
        0xdff01a: "DSKBYTR", #Disk data byte and status read
        0xdff01c: "INTENAR", #Interrupt enable bits read
        0xdff01e: "INTREQR", #Interrupt request bits read
        0xdff020: "DSKPTH", #Disk track buffer pointer (high 5 bits)
        0xdff022: "DSKPTL", #Disk track buffer pointer (low 15 bits)
        0xdff024: "DSKLEN", #Disk track buffer length
        0xdff026: "DSKDAT", #Disk DMA data write
        0xdff028: "REFPTR", #AGA: Refresh pointer
        0xdff02a: "VPOSW", #Write vert most sig. bits (and frame flop)
        0xdff02c: "VHPOSW", #Write vert and horiz pos of beam
        0xdff02e: "COPCON", #Coprocessor control register (CDANG)
        0xdff030: "SERDAT", #Serial port data and stop bits write
        0xdff032: "SERPER", #Serial port period and control
        0xdff034: "POTGO", #Pot count start, pot pin drive enable data
        0xdff036: "JOYTEST", #Write to all 4 joystick/mouse counters at once
        0xdff038: "STREQU", #Strobe for horiz sync with VBLANK and EQU
        0xdff03a: "STRVBL", #Strobe for horiz sync with VBLANK
        0xdff03c: "STRHOR", #Strobe for horiz sync
        0xdff03e: "STRLONG", #Strobe for identification of long/short horiz line
        0xdff040: "BLTCON0", #Blitter control reg 0
        0xdff042: "BLTCON1", #Blitter control reg 1
        0xdff044: "BLTAFWM", #Blitter first word mask for source A
        0xdff046: "BLTALWM", #Blitter last word mask for source A
        0xdff048: "BLTCPTH", #Blitter pointer to source C (high 5 bits)
        0xdff04a: "BLTCPTL", #Blitter pointer to source C (low 15 bits)
        0xdff04c: "BLTBPTH",#	Blitter pointer to source B (high 5 bits)
        0xdff04e: "BLTBPTL",#	Blitter pointer to source B (low 15 bits)
        0xdff050:"BLTAPTH",	#Blitter pointer to source A (high 5 bits)
        0xdff052:"BLTAPTL",	#Blitter pointer to source A (low 15 bits)
        0xdff054:"BLTDPTH",	#Blitter pointer to destination D (high 5 bits)
        0xdff056:"BLTDPTL", #Blitter pointer to destination D (low 15 bits)
        0xdff058:"BLTSIZE", #	Blitter start and size (win/width, height)
        0xdff05a:"BLTCON0L",#	Blitter control 0 lower 8 bits (minterms)
        0xdff05c:"BLTSIZV", #Blitter V size (for 15 bit vert size)
        0xdff05e:"BLTSIZH",#	ECS: Blitter H size & start (for 11 bit H size)
        0xdff060:"BLTCMOD",#Blitter modulo for source C
        0xdff062:"BLTBMOD",#	Blitter modulo for source B
        0xdff064:"BLTAMOD",#D	Blitter modulo for source A
        0xdff066:"BLTDMOD",#	Blitter modulo for destination D
        0xdff068:"RESERVED",#	Reserved
        0xdff06a:"RESERVED",#	Reserved
        0xdff06c:"RESERVED",#	Reserved
        0xdff06e:"RESERVED",#	Reserved
        0xdff070:"BLTCDAT",#	Blitter source C data reg
        0xdff072:"BLTBDAT",#	Blitter source B data reg
        0xdff074:"BLTADAT",#	Blitter source A data reg
        0xdff076:"RESERVED",#	Reserved
        0xdff078:"SPRHDAT",#	AGA: Ext logic UHRES sprite pointer and data identifier
        0xdff07a:"BPLHDAT",#	AGA: Ext logic UHRES bit plane identifier
        0xdff07c:"LISAID",#	AGA: Chip revision level for Denise/Lisa
        0xdff07e:"DSKSYNC",#	Disk sync pattern
        0xdff080:"COP1LCH",#	Write Copper pointer 1 (high 5 bits)
        0xdff082:"COP1LCL",#	Write Copper pointer 1 (low 15 bits)
        0xdff084:"COP2LCH",#	Write Copper pointer 2 (high 5 bits)
        0xdff086:"COP2LCL",#	Write Copper pointer 2 (low 15 bits)
        0xdff088:"COPJMP1",#	Trigger Copper 1 (any value)
        0xdff08a:"COPJMP2",#	Trigger Copper 2 (any value)
        0xdff08c:"COPINS",#	Coprocessor inst fetch identify
        0xdff08e:"DIWSTRT",#	Display window start (upper left vert-hor pos)
        0xdff090:"DIWSTOP",#	Display window stop (lower right vert-hor pos)
        0xdff092:"DDFSTRT",#	Display bitplane data fetch start.hor pos
        0xdff094:"DDFSTOP",#	Display bitplane data fetch stop.hor pos
        0xdff096:"DMACON",#	DMA control write (clear or set)
        0xdff098:"CLXCON",#	Write Sprite collision control bits
        0xdff09a:"INTENA",#	Interrupt enable bits (clear or set bits)
        0xdff09c:"INTREQ",#	Interrupt request bits (clear or set bits)
        0xdff09e:"ADKCON",#	Audio, disk and UART control
        0xdff0a0:"AUD0LCH",#	Audio channel 0 pointer (high 5 bits)
        0xdff0a2:"AUD0LCL",#	Audio channel 0 pointer (low 15 bits)
        0xdff0a4:"AUD0LEN",#	Audio channel 0 length
        0xdff0a6:"AUD0PER",#	Audio channel 0 period
        0xdff0a8:"AUD0VOL",#	Audio channel 0 volume
        0xdff0aa:"AUD0DAT",#	Audio channel 0 data
        0xdff0ac:"RESERVED",#	Reserved
        0xdff0ae:"RESERVED",#	Reserved
        0xdff0b0:"AUD1LCH",#	Audio channel 1 pointer (high 5 bits)
        0xdff0b2:"AUD1LCL",#	Audio channel 1 pointer (low 15 bits)
        0xdff0b4:"AUD1LEN",#	Audio channel 1 length
        0xdff0b6:"AUD1PER",#	Audio channel 1 period
        0xdff0b8:"AUD1VOL",#	Audio channel 1 volume
        0xdff0ba:"AUD1DAT",#	Audio channel 1 data
        0xdff0bc:"RESERVED",#	Reserved
        0xdff0be:"RESERVED",#	Reserved
        0xdff0c0:"AUD2LCH",#	Audio channel 2 pointer (high 5 bits)
        0xdff0c2:"AUD2LCL",#	Audio channel 2 pointer (low 15 bits)
        0xdff0c4:"AUD2LEN",#	Audio channel 2 length
        0xdff0c6:"AUD2PER",#	Audio channel 2 period
        0xdff0c8:"AUD2VOL",#	Audio channel 2 volume
        0xdff0ca:"AUD2DAT",#	Audio channel 2 data
        0xdff0cc:"RESERVED",#	Reserved
        0xdff0ce:"RESERVED",#	Reserved
        0xdff0d0:"AUD3LCH",#	Audio channel 3 pointer (high 5 bits)
        0xdff0d2:"AUD3LCL",#	Audio channel 3 pointer (low 15 bits)
        0xdff0d4:"AUD3LEN",#	Audio channel 3 length
        0xdff0d6:"AUD3PER",#	Audio channel 3 period
        0xdff0d8:"AUD3VOL",#	Audio channel 3 volume
        0xdff0da:"AUD3DAT",#	Audio channel 3 data
        0xdff0dc:"RESERVED",#	Reserved
        0xdff0de:"RESERVED",#	Reserved
        0xdff0e0:"BPL1PTH",#	Bitplane pointer 1 (high 5 bits)
        0xdff0e2:"BPL1PTL",#	Bitplane pointer 1 (low 15 bits)
        0xdff0e4:"BPL2PTH",#	Bitplane pointer 2 (high 5 bits)
        0xdff0e6:"BPL2PTL",#	Bitplane pointer 2 (low 15 bits)
        0xdff0e8:"BPL3PTH",#	Bitplane pointer 3 (high 5 bits)
        0xdff0ea:"BPL3PTL",#	Bitplane pointer 3 (low 15 bits)
        0xdff0ec:"BPL4PTH",#	Bitplane pointer 4 (high 5 bits)
        0xdff0ee:"BPL4PTL",#	Bitplane pointer 4 (low 15 bits)
        0xdff0f0:"BPL5PTH",#	Bitplane pointer 5 (high 5 bits)
        0xdff0f2:"BPL5PTL",#	Bitplane pointer 5 (low 15 bits)
        0xdff0f4:"BPL6PTH",#	Bitplane pointer 6 (high 5 bits)
        0xdff0f6:"BPL6PTL",#	Bitplane pointer 6 (low 15 bits)
        0xdff0f8:"BPL7PTH",#	AGA: Bitplane pointer 7 (high 5 bits)
        0xdff0fa:"BPL7PTL",#	AGA: Bitplane pointer 7 (low 15 bits)
        0xdff0fc:"BPL8PTH",#	AGA: Bitplane pointer 8 (high 5 bits)
        0xdff0fe:"BPL8PTL",#	AGA: Bitplane pointer 8 (low 15 bits)
        0xdff100:"BPLCON0",#	Bitplane depth and screen mode)
        0xdff102:"BPLCON1",#	Bitplane/playfield horizontal scroll values
        0xdff104:"BPLCON2",#	Sprites vs. Playfields priority
        0xdff106:"BPLCON3",#	AGA: Bitplane control reg (enhanced features)
        0xdff108:"BPL1MOD",#	Bitplane modulo (odd planes)
        0xdff10a:"BPL2MOD",#	Bitplane modulo (even planes)
        0xdff10c:"BPLCON4",#	AGA: Bitplane control reg (bitplane & sprite masks)
        0xdff10e:"CLXCON2",#	AGA: Write Extended sprite collision control bits
        0xdff110:"BPL1DAT",#	Bitplane 1 data (parallel to serial convert)
        0xdff112:"BPL2DAT",#	Bitplane 2 data (parallel to serial convert)
        0xdff114:"BPL3DAT",#	Bitplane 3 data (parallel to serial convert)
        0xdff116:"BPL4DAT",#	Bitplane 4 data (parallel to serial convert)
        0xdff118:"BPL5DAT",#	Bitplane 5 data (parallel to serial convert)
        0xdff11a:"BPL6DAT",#	Bitplane 6 data (parallel to serial convert)
        0xdff11c:"BPL7DAT",#	AGA: Bitplane 7 data (parallel to serial convert)
        0xdff11e:"BPL8DAT",#	AGA: Bitplane 8 data (parallel to serial convert)
        0xdff120:"SPR0PTH",#	Sprite 0 pointer (high 5 bits)
        0xdff122:"SPR0PTL",#	Sprite 0 pointer (low 15 bits)
        0xdff124:"SPR1PTH",#	Sprite 1 pointer (high 5 bits)
        0xdff126:"SPR1PTL",#	Sprite 1 pointer (low 15 bits)
        0xdff128:"SPR2PTH",#	Sprite 2 pointer (high 5 bits)
        0xdff12a:"SPR2PTL",#	Sprite 2 pointer (low 15 bits)
        0xdff12c:"SPR3PTH",#	Sprite 3 pointer (high 5 bits)
        0xdff12e:"SPR3PTL",#	Sprite 3 pointer (low 15 bits)
        0xdff130:"SPR4PTH",#	Sprite 4 pointer (high 5 bits)
        0xdff132:"SPR4PTL",#	Sprite 4 pointer (low 15 bits)
        0xdff134:"SPR5PTH",#	Sprite 5 pointer (high 5 bits)
        0xdff136:"SPR5PTL",#	Sprite 5 pointer (low 15 bits)
        0xdff138:"SPR6PTH",#	Sprite 6 pointer (high 5 bits)
        0xdff13a:"SPR6PTL",#	Sprite 6 pointer (low 15 bits)
        0xdff13c:"SPR7PTH",#	Sprite 7 pointer (high 5 bits)
        0xdff13e:"SPR7PTL",#	Sprite 7 pointer (low 15 bits)
        0xdff140:"SPR0POS",#	Sprite 0 vert-horiz start pos data
        0xdff142:"SPR0CTL",#	Sprite 0 position and control data
        0xdff144:"SPR0DATA",#	Sprite 0 low bitplane data
        0xdff146:"SPR0DATB	",#Sprite 0 high bitplane data
        0xdff148:"SPR1POS",#	Sprite 1 vert-horiz start pos data
        0xdff14a:"SPR1CTL",#	Sprite 1 position and control data
        0xdff14c:"SPR1DATA",#	Sprite 1 low bitplane data
        0xdff14e:"SPR1DATB",#	Sprite 1 high bitplane data
        0xdff150:"SPR2POS",#	Sprite 2 vert-horiz start pos data
        0xdff152:"SPR2CTL",#	Sprite 2 position and control data
        0xdff154:"SPR2DATA",#	Sprite 2 low bitplane data
        0xdff156:"SPR2DATB",#	Sprite 2 high bitplane data
        0xdff158:"SPR3POS",#	Sprite 3 vert-horiz start pos data
        0xdff15a:"SPR3CTL",#	Sprite 3 position and control data
        0xdff15c:"SPR3DATA",#	Sprite 3 low bitplane data
        0xdff15e:"SPR3DATB",#	Sprite 3 high bitplane data
        0xdff160:"SPR4POS",#	Sprite 4 vert-horiz start pos data
        0xdff162:"SPR4CTL",#	Sprite 4 position and control data
        0xdff164:"SPR4DATA",#	Sprite 4 low bitplane data
        0xdff166:"SPR4DATB",#	Sprite 4 high bitplane data
        0xdff168:"SPR5POS",#	Sprite 5 vert-horiz start pos data
        0xdff16a:"SPR5CTL",#	Sprite 5 position and control data
        0xdff16c:"SPR5DATA",#	Sprite 5 low bitplane data
        0xdff16e:"SPR5DATB",#	Sprite 5 high bitplane data
        0xdff170:"SPR6POS",#	Sprite 6 vert-horiz start pos data
        0xdff172:"SPR6CTL",#	Sprite 6 position and control data
        0xdff174:"SPR6DATA",#	Sprite 6 low bitplane data
        0xdff176:"SPR6DATB",#	Sprite 6 high bitplane data
        0xdff178:"SPR7POS",#	Sprite 7 vert-horiz start pos data
        0xdff17a:"SPR7CTL",#	Sprite 7 position and control data
        0xdff17c:"SPR7DATA",#	Sprite 7 low bitplane data
        0xdff17e:"SPR7DATB",#	Sprite 7 high bitplane data
        0xdff180:"COLOR00",#	Palette color 00
        0xdff182:"COLOR01",#	Palette color 1
        0xdff184:"COLOR02",#	Palette color 2
        0xdff186:"COLOR03",#	Palette color 3
        0xdff188:"COLOR04",     #	Palette color 4
        0xdff18a:"COLOR05",     #	Palette color 5
        0xdff18c:"COLOR06",     #	Palette color 6
        0xdff18e:"COLOR07",     #	Palette color 7
        0xdff190:"COLOR08",     #",#	Palette color 8
        0xdff192:"COLOR09",     #	Palette color 9
        0xdff194:"COLOR10",     #	Palette color 10
        0xdff196:"COLOR11",     #	Palette color 11
        0xdff198:"COLOR12",     #	Palette color 12
        0xdff19a:"COLOR13",     #	Palette color 13
        0xdff19c:"COLOR14",     #	Palette color 14
        0xdff19e:"COLOR15",     #	Palette color 15
        0xdff1a0:"COLOR16",     #	Palette color 16
        0xdff1a2:"COLOR17",     #	Palette color 17
        0xdff1a4:"COLOR18",     #	Palette color 18
        0xdff1a6:"COLOR19",     #	Palette color 19
        0xdff1a8:"COLOR20",     #	Palette color 20
        0xdff1aa:"COLOR21",     #	Palette color 21
        0xdff1ac:"COLOR22",     #	Palette color 22
        0xdff1ae:"COLOR23",     #	Palette color 23
        0xdff1b0:"COLOR24",     #	Palette color 24
        0xdff1b2:"COLOR25",     #	Palette color 25
        0xdff1b4:"COLOR26",     #	Palette color 26
        0xdff1b6:"COLOR27",     #	Palette color 27
        0xdff1b8:"COLOR28",     #	Palette color 28
        0xdff1ba:"COLOR29",     #	Palette color 29
        0xdff1bc:	"COLOR30",	#Palette color 30
        0xdff1be:	"COLOR31",	#Palette color 31
        # 0xdff1c0	HTOTAL	AGA: Highest number count in horiz line (VARBEAMEN = 1)
        # 0xdff1c2	HSSTOP	AGA: Horiz line pos for HSYNC stop
        # 0xdff1c4	HBSTRT	AGA: Horiz line pos for HBLANK start
        # 0xdff1c6	HBSTOP	AGA: Horiz line pos for HBLANK stop
        # 0xdff1c8	VTOTAL	AGA: Highest numbered vertical line (VARBEAMEN = 1)
        # 0xdff1ca	VSSTOP	AGA: Vert line for Vsync stop
        # 0xdff1cc	VBSTRT	AGA: Vert line for VBLANK start
        # 0xdff1ce	VBSTOP	AGA: Vert line for VBLANK stop
        # 0xdff1d0	SPRHSTRT	AGA: UHRES sprite vertical start
        # 0xdff1d2	SPRHSTOP	AGA: UHRES sprite vertical stop
        # 0xdff1d4	BPLHSTRT	AGA: UHRES bit plane vertical start
        # 0xdff1d6	BPLHSTOP	AGA: UHRES bit plane vertical stop
        # 0xdff1d8	HHPOSW	AGA: DUAL mode hires H beam counter write
        # 0xdff1da	HHPOSR	AGA: DUAL mode hires H beam counter read
        0xdff1dc:	"BEAMCON0", #	Beam counter control register
        # 0xdff1de	HSSTRT	AGA: Horizontal sync start (VARHSY)
        # 0xdff1e0	VSSTRT	AGA: Vertical sync start (VARVSY)
        # 0xdff1e2:	HCENTER	AGA: Horizontal pos for vsync on interlace
        # 0xdff1e4:	DIWHIGH	AGA: Display window upper bits for start/stop
        # 0xdff1e6:	BPLHMOD	AGA: UHRES bit plane modulo
        # 0xdff1e8:	SPRHPTH	AGA: UHRES sprite pointer (high 5 bits)
        # 0xdff1ea:	SPRHPTL	AGA: UHRES sprite pointer (low 15 bits)
        # 0xdff1ec:	BPLHPTH	AGA: VRam (UHRES) bitplane pointer (high 5 bits)
        # 0xdff1ee:	BPLHPTL	AGA: VRam (UHRES) bitplane pointer (low 15 bits)
        0xdff1f0:	"RESERVED",
        0xdff1f2:	"RESERVED",
        0xdff1f4:	"RESERVED",
        0xdff1f6:	"RESERVED",
        0xdff1f8:	"RESERVED",
        0xdff1fa:	"RESERVED",
        # 0xdff1fc:	FMODE	AGA: Write Fetch mode (0=OCS compatible)
        0xdff1fe:	"NO-OP" #	No operation/NULL (Copper NOP instruction)
    }
    def __init__(self):
        super().__init__()


    def decode_instruction(self, data, addr):
        error_value = ('unimplemented', len(data), None, None, None, None)
        if len(data) < 2:
            return error_value

        instruction = struct.unpack_from('>H', data)[0]

        msb = instruction >> 8
        opcode = msb >> 4
        if instruction == 0xFFFE or instruction == 0xFE4E:
            print("0x%X: opcode:0x%X" %(instruction, opcode))

        #print("0x%X 0x%X" % ( addr, instruction))
        return super().decode_instruction(data, addr)
        """
        copperlist:
        dc.w	$9001, $FFFE  ; wait for line 144
        dc.w	$0180, $0F00  ; move red color to 0xdFF180
        dc.w	$A001, $FFFE  ; wait for line 160
        dc.w	$0180, $0FFF  ; move white color to 0xdFF180
        dc.w	$A401, $FFFE  ; wait for line 164
        dc.w	$0180, $000F  ; move blue color to 0xdFF180
        dc.w	$AA01, $FFFE  ; wait for line 170
        dc.w	$0180, $0FFF  ; move white color to 0xdFF180
        dc.w	$AE01, $FFFE  ; wait for line 174 
        dc.w	$0180, $0F00  ; move red color to 0xdFF180
        dc.w	$BE01, $FFFE  ; wait for line 190
        dc.w	$0180, $0000  ; move black color to 0xdFF180
        dc.w	$FFFF, $FFFE  ; end of copper list
        """

class AmigaHunk(BinaryView):
    name = 'Amiga500'
    long_name = 'Amiga 500 Hunk format'
    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['A500'].standalone_platform
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
            if hunktypes[i] == HUNK_CODE:
                print("code hunk found! 0x%X" % idx)
                num_words = struct.unpack(">L",self.data.read(idx,4))[0]
                idx += 4
                code_sz = num_words * 4
                print("Length of code: %d" %code_sz )
                # TODO: fix/identify base address
                self.add_auto_segment( 0x040000, code_sz, idx, code_sz, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
                self.add_user_section("CodeHunk_"+str(i), 0x040000, code_sz, SectionSemantics.ReadOnlyCodeSectionSemantics)
            elif hunktypes[i] == HUNK_DATA:
                print("data hunk found! 0x%X" % idx)
                num_words = struct.unpack(">L",self.data.read(idx,4))[0]
                idx += 4
                data_sz = num_words * 4
                print("Length of data: %d" %data_sz )
                # segment? base addr?
                self.add_user_section("DataHunk_"+str(i), 0x040000, data_sz, SectionSemantics.ReadOnlyDataSectionSemantics)
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
A500.register()
