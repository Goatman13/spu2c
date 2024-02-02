# SPU To C

from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc

#Constants
MASK_ALLSET_128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
MASK_ALLSET_96  = 0xFFFFFFFFFFFFFFFFFFFFFFFF
MASK_ALLSET_64  = 0xFFFFFFFFFFFFFFFF
MASK_ALLSET_32  = 0xFFFFFFFF
MASK_ALLSET_16  = 0xFFFF

def get_reg(reg):

	if reg == 0:
		return "lr"
	elif reg == 1:
		return "sp"
	else:
		return "r{:d}".format(reg)

def get_reg_with_field(reg, field):

	if reg == 0:
		reg = "lr"
	elif reg == 1:
		reg = "sp"
	else:
		reg = "r{:d}".format(reg)
	return reg + "[{:d}]".format(field)

def get_preferred_reg(reg):

	return get_reg_with_field(reg, 0)

def sign_extend_imm10(_16, value):

	if value & 0x200 == 0x200:
		value = (0xFFFFFE00 | value & 0x1FF)
	else:
		value &= 0x1FF
	if _16 == 1:
		value &= 0xFFFF
	return value

def sign_extend_imm16(value):

	if value & 0x8000 == 0x8000:
		return 0xFFFF0000 | value & 0xFFFF
	else:
		return value & 0xFFFF

def imm10_to_signed_string(value):

	sign = ""
	imm = value & 0x3FF
	if (imm > 0x1FF):
		imm = ~imm
		imm &= 0x1FF
		imm += 1
		sign = "-"
	return sign + "0x{:X}".format(imm)

def imm16_to_signed_string(value):

	sign = ""
	imm = value & 0xFFFF
	if (imm > 0x7FFF):
		imm = ~imm
		imm &= 0x7FFF
		imm += 1
		sign = "-"
	return sign + "0x{:X}".format(imm)

def avgb(opcode):

	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	rb     = get_reg(rb)
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[16x8b] = (" + ra + " + " + rb + " + 1) >> 1 (sum before shift is 9 bits value)"

def absdb(opcode):

	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	rb     = get_reg(rb)
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[16x8b] = if (" + ra + " < " + rb + "): " + rb + " - " + ra + ", else: " + ra + " - " + rb

def andc(opcode):

	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	rb     = get_reg(rb)
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[4x32b] = " + ra + " & ~" + rb

def andbi(opcode):

	imm    = (opcode >> 14) & 0xFF
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[16x8b] = " + ra + " & 0x{:X}".format(imm)

def andhi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(1, imm)
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[8x16b] = " + ra + " & 0x{:X}".format(imm)

def andi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(0, imm)
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[4x32b] = " + ra + " & 0x{:X}".format(imm)

def orc(opcode):

	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	rb     = get_reg(rb)
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[4x32b] = " + ra + " | ~" + rb

def orbi(opcode):

	imm    = (opcode >> 14) & 0xFF
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[16x8b] = " + ra + " | 0x{:X}".format(imm)

def orhi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(1, imm)
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[8x16b] = " + ra + " | 0x{:X}".format(imm)

def ori(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(0, imm)
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[4x32b] = " + ra + " | 0x{:X}".format(imm)

def orx(opcode):

	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	rt     = get_reg(rt)
	return rt +"[32b][0] = " + get_reg_with_field(ra,0) + " | " + get_reg_with_field(ra,1) + " | " + get_reg_with_field(ra,2) + " | " + get_reg_with_field(ra,3) + " (lower 96 bits of " + rt + " = 0)"

def xorbi(opcode):

	imm    = (opcode >> 14) & 0xFF
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[16x8b] = " + ra + " ^ 0x{:X}".format(imm)

def xorhi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(1, imm)
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[8x16b] = " + ra + " ^ 0x{:X}".format(imm)

def xori(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(0, imm)
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[4x32b] = " + ra + " ^ 0x{:X}".format(imm)

def eqv(opcode):

	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	rb     = get_reg(rb)
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[4x32b] = " + ra + " ^ ~" + rb + " (If the bit in" + ra + " and " + rb + " are the same, the result bit is 1 else 0)"

def fsmbi(opcode):

	rt      = opcode & 0x7F
	rt      = get_reg(rt)
	i44     = (opcode >> 7)  & 0xF
	i43     = (opcode >> 11) & 0xF
	i42     = (opcode >> 15) & 0xF
	i41     = (opcode >> 19) & 0xF
	mask_44 = 0
	mask_43 = 0
	mask_42 = 0
	mask_41 = 0
	i = 0
	while i < 4:
		mask_temp = i44 & (1<<i)
		if mask_temp != 0:
			mask_44 = mask_44 | (0xFF << (i*8))
		i += 1
	i = 0
	while i < 4:
		mask_temp = i43 & (1<<i)
		if mask_temp != 0:
			mask_43 = mask_43 | (0xFF << (i*8))
		i += 1
	i = 0
	while i < 4:
		mask_temp = i42 & (1<<i)
		if mask_temp != 0:
			mask_42 = mask_42 | (0xFF << (i*8))
		i += 1
	i = 0
	while i < 4:
		mask_temp = i41 & (1<<i)
		if mask_temp != 0:
			mask_41 = mask_41 | (0xFF << (i*8))
		i += 1
	return rt + "[128b] = 0x{:08X}:{:08X}:{:08X}:{:08X}".format(mask_41,mask_42,mask_43,mask_44)

def xsbh(opcode):

	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[8x16b] = SignExtend16(" + ra + " & 0xFF)"

def xshw(opcode):

	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[4x32b] = SignExtend32(" + ra + " & 0xFFFF)"

def xswd(opcode):

	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_reg(ra)
	rt     = get_reg(rt)
	return rt +"[2x64b] = SignExtend64(" + ra + " & 0xFFFFFFFF)"

def ilh(opcode):

	rt     = opcode & 0x7F
	rt     = get_reg(rt)
	imm    = (opcode >> 7) & 0xFFFF
	return rt +"[8x16b] = 0x{:X}".format(imm)

def ilhu(opcode):

	rt     = opcode & 0x7F
	rt     = get_reg(rt)
	imm    = (opcode >> 7) & 0xFFFF
	return rt +"[4x32b] = 0x{:04X}0000".format(imm)

def il(opcode):

	rt     = opcode & 0x7F
	rt     = get_reg(rt)
	val    = (opcode >> 7) & 0xFFFF
	imm    = sign_extend_imm16(val)
	if val > 0x7FFF:
		imms   = imm16_to_signed_string(val)
		return rt +"[4x32b] = 0x{:X}".format(imm) + " (" + imms + ")"
	return rt +"[4x32b] = 0x{:X}".format(imm)

def ila(opcode):

	rt     = opcode & 0x7F
	rt     = get_reg(rt)
	imm    = (opcode >> 7) & 0x3FFFF
	return rt +"[4x32b] = 0x{:X}".format(imm)

def iohl(opcode):

	rt     = opcode & 0x7F
	rt     = get_reg(rt)
	imm    = (opcode >> 7) & 0xFFFF
	return rt +"[4x32b] = " + rt + " | 0x{:X}".format(imm)

def ah(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	rb     = get_reg(rb)
	return rt +"[8x16b] = " + rb + " + " + ra

def a(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	rb     = get_reg(rb)
	return rt +"[4x32b] = " + rb + " + " + ra

def addx(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	rb     = get_reg(rb)
	return rt +"[4x32b] = " + ra + " + " + rb + " + (" + rt + " & 1)"

def sfh(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	rb     = get_reg(rb)
	return rt +"[8x16b] = " + rb + " - " + ra

def sf(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	rb     = get_reg(rb)
	return rt +"[4x32b] = " + rb + " - " + ra

def sfx(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	rb     = get_reg(rb)
	return rt +"[4x32b] = (" + ra + " - " + rb + ") - ((" + rt + " & 1) ^ 1)"

def ahi(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return rt +"[8x16b] = " + ra + " + " + imm

def ai(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return rt +"[4x32b] = " + ra + " + " + imm

def sfhi(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	imm    = (opcode >> 14) & 0x3FF
	imm    =  imm10_to_signed_string(imm)
	return rt +"[8x16b] = " + imm + " - " + ra

def sfi(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	imm    = (opcode >> 14) & 0x3FF
	imm    =  imm10_to_signed_string(imm)
	return rt +"[4x32b] = " + imm + " - " + ra

def bg(opcode):

	rt     = opcode & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	rt     = get_reg(rt)
	ra     = get_reg(ra)
	rb     = get_reg(rb)
	return "[4x32b] if (u32)" + ra + " > (u32)" + rb + ": " + rt + " = 0, else " + rt + " = 0x00000001"

#todo
#def bgx(opcode):
#
#	rt     = opcode & 0x7F
#	ra     = (opcode >> 7) & 0x7F
#	rb     = (opcode >> 14) & 0x7F
#	return "[4x32b] if (u32)" + ra + " > (u32)" + rb + ": " + rt + " = 0, else " + rt + " = 0x00000001"


####################
# Imm shift start: #
####################

def shlqbii(opcode):
	shift  = (opcode >> 14) & 7
	result = MASK_ALLSET_128 << shift
	result &= MASK_ALLSET_128
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a = (result >> 96) & MASK_ALLSET_32
	b = (result >> 64) & MASK_ALLSET_32
	c = (result >> 32) & MASK_ALLSET_32
	d = result & MASK_ALLSET_32
	return "r{:d}[128b] = (r{:d} << {:d}) & 0x{:08X}:{:08X}:{:08X}:{:08X}".format(rt,ra,shift,a,b,c,d)

def shlqbyi(opcode):
	shift  = (opcode >> 14) & 0x1F
	shift  *= 8
	result = MASK_ALLSET_128 << shift
	result &= MASK_ALLSET_128
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a = (result >> 96) & MASK_ALLSET_32
	b = (result >> 64) & MASK_ALLSET_32
	c = (result >> 32) & MASK_ALLSET_32
	d = result & MASK_ALLSET_32
	return "r{:d}[128b] = (r{:d} << {:d}) & 0x{:08X}:{:08X}:{:08X}:{:08X}".format(rt,ra,shift,a,b,c,d)

def shli(opcode):
	shift  = (opcode >> 14) & 0x3F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a      = (MASK_ALLSET_32 << shift) & MASK_ALLSET_32
	return "r{:d}[4x32b] = (r{:d} << {:d}) & 0x{:08X}".format(rt,ra,shift,a)

def shlhi(opcode):
	shift  = (opcode >> 14) & 0x1F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a      = (MASK_ALLSET_16 << shift) & MASK_ALLSET_16
	return "r{:d}[8x16b] = (r{:d} << {:d}) & 0x{:04X}".format(rt,ra,shift,a)

#####################
# Imm rotate start: #
#####################

# Right arithm shift 4x32 by bit
def rotmai(opcode):
	shift  = (0 -(opcode >> 14)) & 0x3F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	#fixme: arithm
	return "r{:d}[4x32b] = (r{:d} >> {:d})".format(rt,ra,shift)

# Right arithm shift 8x16 by bit
def rotmahi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x1F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	#fixme: arithm
	return "r{:d}[8x16b] = (r{:d} >> {:d})".format(rt,ra,shift)

# Right shift 128 by bit
def rotqmbii(opcode):
	shift  = (0 -(opcode >> 14)) & 0x7
	const  = MASK_ALLSET_128
	result = const >> shift
	result &= MASK_ALLSET_128
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a = (result >> 96) & MASK_ALLSET_32
	b = (result >> 64) & MASK_ALLSET_32
	c = (result >> 32) & MASK_ALLSET_32
	d = result & MASK_ALLSET_32
	return "r{:d}[128b] = (r{:d} >> {:d}) & 0x{:08X}:{:08X}:{:08X}:{:08X}".format(rt,ra,shift,a,b,c,d)

# Right shift 128 by byte
def rotqmbyi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x1F
	shift *= 8
	result = MASK_ALLSET_128 >> shift
	result &= MASK_ALLSET_128
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a = (result >> 96) & MASK_ALLSET_32
	b = (result >> 64) & MASK_ALLSET_32
	c = (result >> 32) & MASK_ALLSET_32
	d = result & MASK_ALLSET_32
	return "r{:d}[128b] = (r{:d} >> {:d}) & 0x{:08X}:{:08X}:{:08X}:{:08X}".format(rt,ra,shift,a,b,c,d)

# Right shift 4x32 by bit
def rotmi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x3F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a      = MASK_ALLSET_32 >> shift
	return "r{:d}[4x32b] = (r{:d} >> {:d}) & 0x{:08X}".format(rt,ra,shift,a)

# Right shift 8x16 by bit
def rothmi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x1F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a      = MASK_ALLSET_16 >> shift
	return "r{:d}[8x16b] = (r{:d} >> {:d}) & 0x{:04X}".format(rt,ra,shift,a)

# Left rotate 128 by bit
def rotqbii(opcode):
	shift  = (opcode >> 14) & 0x7
	const  = MASK_ALLSET_128
	result1 = const << shift
	result2 = const >> (128-shift)
	result1 &= MASK_ALLSET_128
	result2 &= MASK_ALLSET_128
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	# fixme: maybe split in 4 rows? Ugly
	return "r{:d}[128b] = (r{:d} << {:d}) & 0x{:032X} | (r{:d} >> {:d}) & 0x{:032X}".format(rt,ra,shift,result1,ra,(128-shift),result2)

# Left rotate 128 by byte
def rotqbyi(opcode):
	shift  = (opcode >> 14) & 0xF
	shift  *= 8
	const  = 0xAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD
	result = const << shift | const >>( 128-shift)
	result &= MASK_ALLSET_128
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	a = (result >> 96) & MASK_ALLSET_32
	b = (result >> 64) & MASK_ALLSET_32
	c = (result >> 32) & MASK_ALLSET_32
	d = result & MASK_ALLSET_32
	return "r{:d}[128b] = r{:d} : {:08X}:{:08X}:{:08X}:{:08X}".format(rt,ra,a,b,c,d)

# Left rotate 4x32 by bit
def roti(opcode):
	#fixme: shift is signed?
	shift  = (opcode >> 14) & 0x1F
	result1 = MASK_ALLSET_32 << shift
	result2 = MASK_ALLSET_32 >> (32-shift)
	result1 &= MASK_ALLSET_32
	result2 &= MASK_ALLSET_32
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[4x32b] = (r{:d} << {:d}) & 0x{:08X} | (r{:d} >> {:d}) & 0x{:08X}".format(rt,ra,shift,result1,ra,(32-shift),result2)

# Left rotate 8x16 by bit
def rothi(opcode):
	shift  = (opcode >> 14) & 0xF
	result1 = MASK_ALLSET_16 << shift
	result2 = MASK_ALLSET_16 >> (16-shift)
	result1 &= MASK_ALLSET_16
	result2 &= MASK_ALLSET_16
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	# we can have special case here:
	if shift == 8:
		return "r{:d}[8x16b] = byteswap16(r{:d})".format(rt,ra)
	return "r{:d}[8x16b] = (r{:d} << {:d}) & 0x{:04X} | (r{:d} >> {:d}) & 0x{:04X}".format(rt,ra,shift,result1,ra,(16-shift),result2)

#########################
# Non imm rotate start: #
#########################

# Right arithm shift 4x32 by bit from rb
def rotma(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	#fixme: arithm
	return "r{:d}[4x32b] = r{:d} >> -(r{:d}) & 0x3F".format(rt,ra,rb)

# Right arithm shift 8x16 by bit from rb
def rotmah(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	#fixme: arithm
	return "r{:d}[8x16b] = r{:d} >> -(r{:d}) & 0x1F".format(rt,ra,rb)

# Right shift 128 by bit from rb
def rotqmbi(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[128b] = r{:d} >> -(r{:d}) & 7".format(rt,ra,rb)

# Right shift 128 by byte from rb
# fixme rotqmby
def rotqmbybi(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[128b] = r{:d} >> ( -(r{:d}) & 0x1F) * 8".format(rt,ra,rb)

# Right shift 128 by byte from rb
# fixme rotqmbybi
def rotqmby(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[128b] = r{:d} >> ( -(r{:d}) & 0x1F) * 8".format(rt,ra,rb)

# Right logical shift 4x32 by bit from rb
def rotm(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[4x32b] = r{:d} >> -(r{:d}) & 0x3F".format(rt,ra,rb)

# Right logical shift 8x16 by bit from rb
def rothm(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[8x16b] = r{:d} >> -(r{:d}) & 0x1F".format(rt,ra,rb)

# Left rotate 128 by bit from rb
def rotqbi(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[128b] = r{:d} << (r{:d} & 7) | r{:d} >> 128 - (r{:d} & 7)".format(rt,ra,rb,ra,rb)

#rotqbybi

# Left rotate 128 by byte from rb
def rotqby(opcode):
	rb  = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[128b] = r{:d} << (r{:d} & 0xF) * 8 | r{:d} >> 128 - ((r{:d} & 0xF) * 8)".format(rt,ra,rb,ra,rb)

# Left rotate 4x32 by bit from rb
def rot(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[4x32b] = r{:d} << (r{:d} & 0x1F) | r{:d} >> 32 - (r{:d} & 0x1F)".format(rt,ra,rb,ra,rb)

# Left rotate 8x16 by bit from rb
def roth(opcode):
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	return "r{:d}[8x16b] = r{:d} << (r{:d} & 0xF) | r{:d} >> 16 - (r{:d} & 0xF)".format(rt,ra,rb,ra,rb)

###################
# Branches start: #
###################

# Warning! Code for branches assume that SPU program is PS3 version.
# This mean address is AND with 0x3FFFC.
# This should be changed if you are working with hardware different than PS3.

# Branch indirect (always)
def bi(opcode):
	ra     = (opcode >> 7) & 0x7F
	ra     = get_preferred_reg(ra)
	return "PC = " + ra + " & 0x3FFFC"

# Branch indirect and link if external data
def bisled(addr, opcode):
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_preferred_reg(ra)
	rt     = get_preferred_reg(rt)
	return "if ext_data: PC = " + ra + "& 0x3FFFC, ", + rt + " = 0x{:05X}".format(addr + 4)

# Branch indirect and set link (always)
def bisl(addr, opcode):
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_preferred_reg(ra)
	rt     = get_preferred_reg(rt)
	return "PC = " + ra + " & 0x3FFFC, " + rt + " = 0x{:05X}".format(addr + 4)

# Branch indirect if zero
def biz(addr, opcode):
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_preferred_reg(ra)
	rt     = get_preferred_reg(rt)
	return "if " + rt + " == 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

# Branch indirect if not zero
def binz(addr, opcode):
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_preferred_reg(ra)
	rt     = get_preferred_reg(rt)
	return "if " + rt + " != 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

# Branch indirect if zero halfword
def bihz(addr, opcode):
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_preferred_reg(ra)
	rt     = get_preferred_reg(rt)
	return "if (" + rt + "[32b] & 0xFFFF) == 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

# Branch indirect if not zero halfword
def bihnz(addr, opcode):
	ra     = (opcode >> 7) & 0x7F
	rt     = opcode & 0x7F
	ra     = get_preferred_reg(ra)
	rt     = get_preferred_reg(rt)
	return "if (" + rt + "[32b] & 0xFFFF) != 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

def shufb(opcode):

	rt     = (opcode >> 21) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rc     = opcode & 0x7F
	rt     = get_reg(rt)
	rb     = get_reg(rb)
	ra     = get_reg(ra)
	rc     = get_reg(rc)
	cmt    = ".\nfor (field = 0; field <= 15; field++)\n{\n\tx = " + rc + ".byte[field]\n\tif (x < 0x80)\n\t{\n\t    if      (x & 0x10) == 0x00) {" + rt + ".byte[field] = " + ra + ".byte[x & 0x0f];}\n\t    else if (x & 0x10) == 0x10) {" + rt + ".byte[field] = " + rb + ".byte[x & 0x0f];}\n\t}\n\telse\n\t{\n\t    if      (x >= 0x80 && x < 0xC0) {" + rt + ".byte[field] = 0x00;}\n\t    else if (x >= 0xC0 && x < 0xE0) {" + rt + ".byte[field] = 0xFF;}\n\t    else if (x >= 0xE0)             {" + rt + ".byte[field] = 0x80;}\n\t}\n}"
	cmt2    = "Are you sure you want to place this comment?\nfor (field = 0; field <= 15; field++)\n{\n    x = " + rc + ".byte[field]\n    if (x < 0x80)\n    {\n        if      (x & 0x10) == 0x00) {" + rt + ".byte[field] = " + ra + ".byte[x & 0x0f];}\n        else if (x & 0x10) == 0x10) {" + rt + ".byte[field] = " + rb + ".byte[x & 0x0f];}\n    }\n    else\n    {\n        if      (x >= 0x80 && x < 0xC0) {" + rt + ".byte[field] = 0x00;}\n        else if (x >= 0xC0 && x < 0xE0) {" + rt + ".byte[field] = 0xFF;}\n        else if (x >= 0xE0)             {" + rt + ".byte[field] = 0x80;}\n    }\n}"

	answer = ask_yn(0, cmt2)
	if answer < 1:
		return 1
	return cmt

def selb(opcode):

	rt     = (opcode >> 21) & 0x7F
	rb     = (opcode >> 14) & 0x7F
	ra     = (opcode >> 7) & 0x7F
	rc     = opcode & 0x7F
	rt     = get_reg(rt)
	rb     = get_reg(rb)
	ra     = get_reg(ra)
	rc     = get_reg(rc)
	return rt + "[16x8b] = " + rc + " & " + rb + " | ~" + rc + " & " + ra + " (if bit in " + rc + " is 1 take bit from " + rb + ", else from " + ra + ")"


# Todo:
# imm:
# mpyi, mpyui
# non imm:
# shifts, compares, rotqbybi, add which field is responsible for for shoft/rot count!
# else: simplify x by 0

def SPUAsm2C(addr):

	opcode = get_wide_dword(addr)
	opcode_name = print_insn_mnem(addr)
	if opcode_name == "fsmbi":
		return fsmbi(opcode)
	elif opcode_name == "avgb":
		return avgb(opcode)
	elif opcode_name == "absdb":
		return absdb(opcode)
	elif opcode_name == "andc":
		return andc(opcode)
	elif opcode_name == "andbi":
		return andbi(opcode)
	elif opcode_name == "andhi":
		return andhi(opcode)
	elif opcode_name == "andi":
		return andi(opcode)
	elif opcode_name == "orc":
		return orc(opcode)
	elif opcode_name == "orbi":
		return orbi(opcode)
	elif opcode_name == "orhi":
		return orhi(opcode)
	elif opcode_name == "ori":
		return ori(opcode)
	elif opcode_name == "orx":
		return orx(opcode)
	elif opcode_name == "xorbi":
		return xorbi(opcode)
	elif opcode_name == "xorhi":
		return xorhi(opcode)
	elif opcode_name == "xori":
		return xori(opcode)
	elif opcode_name == "eqv":
		return eqv(opcode)
	elif opcode_name == "ilh":
		return ilh(opcode)
	elif opcode_name == "ilhu":
		return ilhu(opcode)
	elif opcode_name == "il":
		return il(opcode)
	elif opcode_name == "ila":
		return ila(opcode)
	elif opcode_name == "iohl":
		return iohl(opcode)
	elif opcode_name == "ah":
		return ah(opcode)
	elif opcode_name == "a":
		return a(opcode)
	elif opcode_name == "addx":
		return addx(opcode)
	elif opcode_name == "sfh":
		return sfh(opcode)
	elif opcode_name == "sf":
		return sf(opcode)
	elif opcode_name == "sfx":
		return sfx(opcode)
	elif opcode_name == "ahi":
		return ahi(opcode)
	elif opcode_name == "ai":
		return ai(opcode)
	elif opcode_name == "sfhi":
		return sfhi(opcode)
	elif opcode_name == "sfi":
		return sfi(opcode)
	elif opcode_name == "bg":
		return bg(opcode)
	elif opcode_name == "shlqbyi":
		return shlqbyi(opcode)
	elif opcode_name == "shlqbii":
		return shlqbii(opcode)
	elif opcode_name == "shli":
		return shli(opcode)
	elif opcode_name == "shlhi":
		return shlhi(opcode)
	elif opcode_name == "rotmai":
		return rotmai(opcode)
	elif opcode_name == "rotmahi":
		return rotmahi(opcode)
	elif opcode_name == "rotqmbii":
		return rotqmbii(opcode)
	elif opcode_name == "rotqmbyi":
		return rotqmbyi(opcode)
	elif opcode_name == "rotmi":
		return rotmi(opcode)
	elif opcode_name == "rothmi":
		return rothmi(opcode)
	elif opcode_name == "rotqbii":
		return rotqbii(opcode)
	elif opcode_name == "rotqbyi":
		return rotqbyi(opcode)
	elif opcode_name == "roti":
		return roti(opcode)
	elif opcode_name == "rothi":
		return rothi(opcode)
	elif opcode_name == "rotma":
		return rotma(opcode)
	elif opcode_name == "rotmah":
		return rotmah(opcode)
	elif opcode_name == "rotqmbi":
		return rotqmbi(opcode)
	elif opcode_name == "rotqmbybi":
		return rotqmbybi(opcode)
	elif opcode_name == "rotqmby":
		return rotqmby(opcode)
	elif opcode_name == "rotm":
		return rotm(opcode)
	elif opcode_name == "rothm":
		return rothm(opcode)
	elif opcode_name == "rotqbi":
		return rotqbi(opcode)
	elif opcode_name == "rotqby":
		return rotqby(opcode)
	elif opcode_name == "rot":
		return rot(opcode)
	elif opcode_name == "roth":
		return roth(opcode)
	elif opcode_name == "bi":
		return bi(opcode)
	elif opcode_name == "bisled":
		return bisled(addr, opcode)
	elif opcode_name == "bisl":
		return bisl(addr, opcode)
	elif opcode_name == "biz":
		return biz(addr, opcode)
	elif opcode_name == "binz":
		return binz(addr, opcode)
	elif opcode_name == "bihz":
		return bihz(addr, opcode)
	elif opcode_name == "bihnz":
		return bihnz(addr, opcode)
	elif opcode_name == "xsbh":
		return xsbh(opcode)
	elif opcode_name == "xshw":
		return xshw(opcode)
	elif opcode_name == "xswd":
		return xswd(opcode)
	elif opcode_name == "shufb":
		return shufb(opcode)
	elif opcode_name == "selb":
		return selb(opcode)

	return 0

def run_task(start_addr, end_addr, always_insert_comment):

	# convert all instructions within the bounds
	addr = start_addr
	while(addr < end_addr):
		print_str = SPUAsm2C(addr)
		if(print_str != 0 and print_str != 1):
			set_cmt(addr, print_str, False)
		elif (print_str == 0 and always_insert_comment == True):
			msg("0x{:X}: Error converting SPU to C code\n".format(addr))
		addr += 4


def PluginMain():

	# select current line or selected lines
	always_insert_comment = False
	start_addr = read_selection_start()
	end_addr = read_selection_end()
	if(start_addr == BADADDR):
		start_addr = get_screen_ea();
		end_addr = start_addr + 4;
		always_insert_comment = True

	run_task(start_addr, end_addr, always_insert_comment)


def PluginMainF():

	# convert current function
	p_func = get_func(get_screen_ea());
	if(p_func == None):
		msg("Not in a function, so can't do SPU to C conversion for the current function!\n");
		return;
	start_addr = p_func.start_ea;
	end_addr = p_func.end_ea;
	always_insert_comment = False;

	run_task(start_addr, end_addr, always_insert_comment)


#/***************************************************************************************************
#*
#*	Strings required for IDA Pro's PLUGIN descriptor block
#*
#***************************************************************************************************/
#
G_PLUGIN_COMMENT = "SPU To C Conversion Assist"
G_PLUGIN_HELP = "This plugin assists in converting SPU instructions into their relevant C code.\nIt is especially useful for the tricky bit manipulation and shift instructions.\n"
G_PLUGIN_NAME = "SPU To C: Selected Lines"

#/***************************************************************************************************
#*
#*	This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
#*
#***************************************************************************************************/

class ActionHandler(idaapi.action_handler_t):

    def __init__(self, callback):

        idaapi.action_handler_t.__init__(self)
        self.callback = callback

    def activate(self, ctx):

        self.callback()
        return 1

    def update(self, ctx):

        return idaapi.AST_ENABLE_ALWAYS

def register_actions():

    actions = [
        {
            'id': 'start:plg',
            'name': G_PLUGIN_NAME,
            'hotkey': 'F10',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMain,
            'menu_location': 'Start Plg'
        },
        {
            'id': 'start:plg1',
            'name': 'spu2c unimplemented',
            'hotkey': 'Alt-Shift-F10',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMainF,
            'menu_location': 'Start Plg1'
        }
    ]

    for action in actions:

        if not idaapi.register_action(idaapi.action_desc_t(
            action['id'], # Must be the unique item
            action['name'], # The name the user sees
            ActionHandler(action['callback']), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'] # A comment, if any (optional)
        )):

            print('Failed to register ' + action['id'])

        if not idaapi.attach_action_to_menu(
            action['menu_location'], # The menu location
            action['id'], # The unique function ID
            0):

            print('Failed to attach to menu '+ action['id'])

class spu_helper_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = G_PLUGIN_COMMENT
	help = G_PLUGIN_HELP
	wanted_name = G_PLUGIN_NAME
	wanted_hotkey = "F10"

	def init(self):
		if (idaapi.ph.id == idaapi.PLFM_SPU):
			register_actions()
			idaapi.msg("spu2c: loaded\n")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP

	def run(self, arg):
		idaapi.msg("spu2c: run\n")

	def term(self):
		pass

def PLUGIN_ENTRY():
	return spu_helper_t()
