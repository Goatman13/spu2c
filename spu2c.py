# SPU To C

FLT_CONVERSION_SUPPORT = 1
from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc

try:
	import numpy
except ImportError:
	FLT_CONVERSION_SUPPORT = 0
	warning("WARNING:\nspu2c: numpy not found!\nFloat conversion opcodes unsupported!")

#Constants
MASK_ALLSET_128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
MASK_ALLSET_96  = 0xFFFFFFFFFFFFFFFFFFFFFFFF
MASK_ALLSET_64  = 0xFFFFFFFFFFFFFFFF
MASK_ALLSET_32  = 0xFFFFFFFF
MASK_ALLSET_16  = 0xFFFF
UP   = 0
DOWN = 1

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

def get_channel(ca):

	if ca < 31:
		ca_tbl = ["event_status", "event_mask", "event_ack", "signal_notify1", "signal_notify2", "ch5", "ch6", "decrementer", "decrementer", "multisource_sync_req",
		"ch10", "event_mask", "tag_mask", "machine_status", "srr0", "srr0", "ls_address", "mfc_eah", "mfc_eal", "mfc_size",
		"tag_id", "mfc_cmd", "tag_mask", "tag_update", "tag_status", "list_stall_status", "list_stall_ack", "atomic_status", "out_mailbox", "in_mailbox",
		"intr_out_mailbox"]
		return ca_tbl[ca]
	elif ca == 69:
		ca = "set_bkmk_tag"
	elif ca == 70:
		ca = "perf_monitor_start_event"
	elif ca == 71:
		ca = "perf_monitor_stop_event"
	elif ca == 74:
		ca = "rng"
	else:
		ca = "ch{:d}".format(ca)
	return ca
	
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

def check_abort_shufb(addr, end, msk_reg, direction):
	
	while addr != end:
		opcode   = get_wide_dword(addr)
		if opcode >> 31 == 1:
			# RRRR format
			test_reg = (opcode >> 21) & 0x7F
		else:
			test_reg = opcode & 0x7F

		if test_reg == msk_reg:
			return 1

		if direction == DOWN:
			addr += 4
		else:
			addr -= 4
	return 0

def shufb_patterns(addr, opcode):
	
	msk_reg = opcode & 0x7F
	rt = get_reg((opcode >> 21) & 0x7F)
	rb = get_reg((opcode >> 14) & 0x7F)
	ra = get_reg((opcode >> 7) & 0x7F)
	limit = addr - 0x500
	msk = 0
	full_string = ".\n"
	while addr > limit:
		# addr + 4 because opcode at address with cref is ok.
		xref_test = get_first_fcref_to(addr+4)
		
		# branch target, we need to check xrefs.
		if xref_test != BADADDR:
			abort = 1
			
			# Test xrefs.
			# Todo 0018064 in pemu 3 elf.
			# When we are sure that current address is unreachable by
			# any other way than that branch, we are safe to go.
			#
			# Good test case for successful abort in pemu 5 00007374, etc.
			while xref_test != BADADDR:
				if xref_test > addr+4:
					direction = DOWN
				else:
					direction = UP
				abort = check_abort_shufb(addr+4, xref_test, msk_reg, direction)
				if abort != 0:
					print("shufb: Aborting due to CREF at 0x{:X}, from 0x{:X}".format(addr+4, xref_test))
					return 0
				xref_test = get_next_fcref_to(addr+4, xref_test)

		test_op = get_wide_dword(addr)
		if (test_op >> 31) & 1 == 1:
			# RRRR
			target_reg = (test_op >> 21) & 0x7F
		else:
			target_reg = test_op & 0x7F
		
		if target_reg == msk_reg:
			print("shufb: Using opcode from 0x{:X} as a mask loader".format(addr))
			name = print_insn_mnem(addr)
			# Todo il, ilhu, more?
			if name == "ila":
				msk = (test_op >> 7) & 0x3FFFF
				print("shufb: Pre shift mask from ila opcode = 0x{:08X}".format(msk))
				msk = (msk | msk << 32 | msk << 64 | msk << 96)
			if name == "ilh":
				msk = (test_op >> 7) & 0xFFFF
				msk = msk | msk << 16
				print("shufb: Pre shift mask from ilh opcode = 0x{:08X}".format(msk))
				msk = (msk | msk << 32 | msk << 64 | msk << 96)
			elif name in ["lqa", "lqr"]:
				msk_addr = get_operand_value(addr, 1);
				msk = get_wide_dword(msk_addr) << 96 | get_wide_dword(msk_addr+4) << 64 | get_wide_dword(msk_addr+8) << 32 | get_wide_dword(msk_addr+12)
				print("shufb: Using mask from lq opcode, mask at 0x{:X}".format(msk_addr))
			elif name in ["cbd", "chd", "cwd", "cdd"]:
				print("shufb: Generating mask from Generate Controls instruction")
				base   = 0x101112131415161718191A1B1C1D1E1F
				if name == "cbd":
					shift = ((15 - (get_operand_value(addr, 1) & 0x0F)) * 8)
					base  = base & ~(0xFF << shift)
					msk   = 0x03 << shift
				elif name == "chd":
					shift = ((14 - (get_operand_value(addr, 1) & 0x0E)) * 8)
					base  = base & ~(MASK_ALLSET_16 << shift)
					msk   = 0x0203 << shift
				elif name == "cwd":
					shift = ((12 - (get_operand_value(addr, 1) & 0x0C)) * 8)
					base  = base & ~(MASK_ALLSET_32 << shift)
					msk   = 0x00010203 << shift
				else:
					shift = ((8 - (get_operand_value(addr, 1) & 0x08)) * 8)
					base  = base & ~(MASK_ALLSET_64 << shift)
					msk   = 0x0001020304050607 << shift
				msk  |= base
				ctrl_reg = get_reg((test_op >> 7) & 0x7F)
				if 	ctrl_reg != "sp":
					full_string += "shufb: WARNING!\n" + name + " at 0x{:X} is not using sp register as a base!\n".format(addr)
					full_string += "shufb: Mask can be inaccurate if " + ctrl_reg + "[32b][0] & 0x0F != 0\n"
			elif name == "orbi":
				tra    = (test_op >> 7) & 0x7F
				timm   = (test_op >> 14) & 0xFF
				timm   = (timm | timm << 8 | timm << 16 | timm << 24) & MASK_ALLSET_32
				timm   = (timm | timm << 32 | timm << 64 | timm << 96) & MASK_ALLSET_128
				taddr  = addr - 4
				tlimit = taddr - 0x300
				while taddr > tlimit:
					# taddr + 4 because opcode at address with cref is ok. 
					if get_first_fcref_to(taddr + 4) != BADADDR:
						# branch target, we need to abandon searching.
						# Result can be inaccurate.
						print("shufb: Aborting post orbi search due to CREF AT 0x{:X}".format(taddr))
						return 0
					test_op = get_wide_dword(taddr)
					if (test_op >> 31) & 1 == 1:
						# RRRR
						target_reg = (test_op >> 21) & 0x7F
					else:
						target_reg = test_op & 0x7F
					
					if target_reg == tra:
						print("shufb: Orbi is using opcode from 0x{:X} as a mask loader".format(taddr))
						name = print_insn_mnem(taddr)
						if name == "ila":
							msk = (test_op >> 7) & 0x3FFFF
							print("shufb: Orbi pre shift mask from ila opcode = 0x{:08X}".format(msk))
							msk  = (msk | msk << 32 | msk << 64 | msk << 96)
							msk |= timm
							break
						#Unsafe, disabled for now
						#elif name in ["lqa", "lqr"]:
						#	msk_addr = get_operand_value(taddr, 1);
						#	msk  = get_wide_dword(msk_addr) << 96 | get_wide_dword(msk_addr+4) << 64 | get_wide_dword(msk_addr+8) << 32 | get_wide_dword(msk_addr+12)
						#	msk |= timm
						#	print("shufb!!!!: Using mask from lq opcode at 0x{:X}".format(msk_addr))
						#	break
						else:
							print("shufb: Aborting, orbi use unsupported mask base opcode")
							return 0
					taddr -= 4
				if taddr == tlimit:
					print("shufb: Aborting in orbi path, opcode with mask not found")
					return 0					
			else:
				print("shufb: Can't resolve mask, unsupported opcode")
				return 0
			break
		addr -= 4
		if addr == limit:
			print("shufb: Aborting, opcode with mask not found")
			return 0
	print("shufb: Mask = 0x{:032X}".format(msk))
	field  = 0
	result = 0
	space  = " "
	new_line    = "\n"
	while field <= 15:
		if field > 9:
			space = ""
		if field == 15:
			new_line = ""
		x = (msk >> (15 - field) * 8) & 0xFF
		#print("X = 0x{:02X}".format(x))
		if x < 0x80:
			if x & 0x10 == 0x00:
				full_string += rt + " byte[{:d}] ".format(field,) + space + "= byte[{:d}] from ".format(x&0xF) + ra + new_line
				result |= ((x & 0x0F | 0xA0) << ((15 - field) * 8))
			else: 
				full_string += rt + " byte[{:d}] ".format(field,) + space + "= byte[{:d}] from ".format(x&0xF) + rb + new_line
				result |= ((x & 0x0F | 0xB0) << ((15 - field) * 8))
		else:
			if x < 0xC0:
				full_string += rt + " byte[{:d}] ".format(field,) + space + "= 0x00" + new_line
				result |= (0x00 << ((15 - field) * 8))
			elif x >= 0xC0 and x < 0xE0:
				full_string += rt + " byte[{:d}] ".format(field,) + space + "= 0xFF" + new_line
				result |= (0xFF << ((15 - field) * 8))
			else:
				full_string += rt + " byte[{:d}] ".format(field,) + space + "= 0x80" + new_line
				result |= (0x80 << ((15 - field) * 8))
		field += 1
	#print("MASK 0x{:032X}".format(result))
	#print(full_string)
	return full_string
		

def avgb(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[16x8b] = (" + ra + " + " + rb + " + 1) >> 1 (sum before shift is 9 bits value)"

def absdb(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[16x8b] = if (" + ra + " < " + rb + "): " + rb + " - " + ra + ", else: " + ra + " - " + rb

def andc(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + ra + " & ~" + rb

def andbi(opcode):

	imm    = (opcode >> 14) & 0xFF
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[16x8b] = " + ra + " & 0x{:02X}".format(imm)

def andhi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(1, imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[8x16b] = " + ra + " & 0x{:04X}".format(imm)

def andi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(0, imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + ra + " & 0x{:08X}".format(imm)

def orc(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + ra + " | ~" + rb

def orbi(opcode):

	imm    = (opcode >> 14) & 0xFF
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[16x8b] = " + ra + " | 0x{:X}".format(imm)

def orhi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(1, imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[8x16b] = " + ra + " | 0x{:X}".format(imm)

def ori(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(0, imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + ra + " | 0x{:X}".format(imm)

def orx(opcode):

	ra     = (opcode >> 7) & 0x7F
	rt     = get_reg(opcode & 0x7F)
	return rt +"[32b][0] = " + get_reg_with_field(ra,0) + " | " + get_reg_with_field(ra,1) + " | " + get_reg_with_field(ra,2) + " | " + get_reg_with_field(ra,3) + " (lower 96 bits of " + rt + " = 0)"

def xorbi(opcode):

	imm    = (opcode >> 14) & 0xFF
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[16x8b] = " + ra + " ^ 0x{:X}".format(imm)

def xorhi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(1, imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[8x16b] = " + ra + " ^ 0x{:X}".format(imm)

def xori(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(0, imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + ra + " ^ 0x{:X}".format(imm)

def eqv(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + ra + " ^ ~" + rb + " (If the bit in" + ra + " and " + rb + " are the same, the result bit is 1 else 0)"

def fsmbi(opcode):

	rt      = get_reg(opcode & 0x7F)
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

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[8x16b] = SignExtend16(" + ra + " & 0xFF)"

def xshw(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = SignExtend32(" + ra + " & 0xFFFF)"

def xswd(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[2x64b] = SignExtend64(" + ra + " & 0xFFFFFFFF)"

def ilh(opcode):

	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 7) & 0xFFFF
	return rt +"[8x16b] = 0x{:X}".format(imm)

def ilhu(opcode):

	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 7) & 0xFFFF
	return rt +"[4x32b] = 0x{:04X}0000".format(imm)

def il(opcode):

	rt     = get_reg(opcode & 0x7F)
	val    = (opcode >> 7) & 0xFFFF
	imm    = sign_extend_imm16(val)
	if val > 0x7FFF:
		imms   = imm16_to_signed_string(val)
		return rt +"[4x32b] = 0x{:X}".format(imm) + " (" + imms + ")"
	return rt +"[4x32b] = 0x{:X}".format(imm)

def ila(opcode):

	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 7) & 0x3FFFF
	return rt +"[4x32b] = 0x{:X}".format(imm)

def iohl(opcode):

	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 7) & 0xFFFF
	return rt +"[4x32b] = " + rt + " | 0x{:X}".format(imm)

def ah(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[8x16b] = " + rb + " + " + ra

def a(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + rb + " + " + ra

def addx(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + ra + " + " + rb + " + (" + rt + " & 1)"

def sfh(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[8x16b] = " + rb + " - " + ra

def sf(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = " + rb + " - " + ra

def sfx(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4x32b] = (" + ra + " - " + rb + ") - ((" + rt + " & 1) ^ 1)"

def ahi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return rt +"[8x16b] = " + ra + " + " + imm

def ai(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return rt +"[4x32b] = " + ra + " + " + imm

def sfhi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return rt +"[8x16b] = " + imm + " - " + ra

def sfi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return rt +"[4x32b] = " + imm + " - " + ra

def bg(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[4x32b] if (u32)" + ra + " > (u32)" + rb + ": " + rt + " = 0, else " + rt + " = 0x00000001"

#todo
#def bgx(opcode):
#
#	rt     = opcode & 0x7F
#	ra     = (opcode >> 7) & 0x7F
#	rb     = (opcode >> 14) & 0x7F
#	return "[4x32b] if (u32)" + ra + " > (u32)" + rb + ": " + rt + " = 0, else " + rt + " = 0x00000001"

def mpy(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = (s16)(" + ra + " & 0xFFFF) * (s16)(" + rb + " & 0xFFFF)"

def mpyu(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = (" + ra + " & 0xFFFF) * (" + rb + " & 0xFFFF)"

# signed rc? 
def mpya(opcode):

	rt     = get_reg((opcode >> 21) & 0x7F)
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rc     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = ((s16)(" + ra + " & 0xFFFF) * (s16)(" + rb + " & 0xFFFF)) + " + rc

# signed? 
def mpyh(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = ((((" + ra + " >> 16) & 0xFFFF) * (" + rb + " & 0xFFFF)) << 16) & 0xFFFF0000"

# signed? 
def mpys(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = sign_extend32(((" + ra + " & 0xFFFF) * (" + rb + " & 0xFFFF)) >> 16)"

def mpyhh(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = (s16)((" + ra + " >> 16) & 0xFFFF) * (s16)((" + rb + " >> 16) & 0xFFFF)"

# signed rt? 
def mpyhha(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = (s16)((" + ra + " >> 16) & 0xFFFF) * (s16)((" + rb + " >> 16) & 0xFFFF) + " + rt

def mpyhhu(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = ((" + ra + " >> 16) & 0xFFFF) * ((" + rb + " >> 16) & 0xFFFF)"

def mpyhhau(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = ((" + ra + " >> 16) & 0xFFFF) * ((" + rb + " >> 16) & 0xFFFF) + " + rt

def mpyi(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = (s16)(" + ra + " & 0xFFFF) * " + imm

def mpyui(opcode):

	imm    = (opcode >> 14) & 0x3FF
	imm    = sign_extend_imm10(1, imm)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = (" + ra + " & 0xFFFF) * 0x{:X}".format(imm)


####################
# Imm shift start: #
####################

def shlqbii(opcode):
	shift  = (opcode >> 14) & 7
	result = MASK_ALLSET_128 << shift
	result &= MASK_ALLSET_128
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a      = result & MASK_ALLSET_32
	return rt + "[128b] = (" + ra + " << {:d}) & 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:{:08X}".format(shift,a)

def shlqbyi(opcode):
	shift  = (opcode >> 14) & 0x1F
	shift  *= 8
	result = MASK_ALLSET_128 << shift
	result &= MASK_ALLSET_128
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a      = (result >> 96) & MASK_ALLSET_32
	b      = (result >> 64) & MASK_ALLSET_32
	c      = (result >> 32) & MASK_ALLSET_32
	d      = result & MASK_ALLSET_32
	return rt + "[128b] = (" + ra + " << {:d}) & 0x{:08X}:{:08X}:{:08X}:{:08X}".format(shift,a,b,c,d)

def shli(opcode):
	shift  = (opcode >> 14) & 0x3F
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a      = (MASK_ALLSET_32 << shift) & MASK_ALLSET_32
	return rt + "[4x32b] = (" + ra + " << {:d}) & 0x{:08X}".format(shift,a)

def shlhi(opcode):
	shift  = (opcode >> 14) & 0x1F
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a      = (MASK_ALLSET_16 << shift) & MASK_ALLSET_16
	return rt + "[8x16b] = (" + ra + " << {:d}) & 0x{:04X}".format(shift,a)

#####################
# Imm rotate start: #
#####################

# Right arithm shift 4x32 by bit
def rotmai(opcode):
	shift  = (0 -(opcode >> 14)) & 0x3F
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	#fixme: arithm
	return rt + "[4x32b] = (" + ra + " >> {:d})".format(shift)

# Right arithm shift 8x16 by bit
def rotmahi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x1F
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	#fixme: arithm
	return rt + "[8x16b] = (" + ra + " >> {:d})".format(shift)

# Right shift 128 by bit
def rotqmbii(opcode):
	shift  = (0 -(opcode >> 14)) & 0x7
	const  = MASK_ALLSET_128
	result = const >> shift
	result &= MASK_ALLSET_128
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a = (result >> 96) & MASK_ALLSET_32
	return rt + "[128b] = (" + ra + " >> {:d}) & 0x{:08X}:FFFFFFFF:FFFFFFFF:FFFFFFFF".format(shift,a)

# Right shift 128 by byte
def rotqmbyi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x1F
	shift *= 8
	result = MASK_ALLSET_128 >> shift
	result &= MASK_ALLSET_128
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a = (result >> 96) & MASK_ALLSET_32
	b = (result >> 64) & MASK_ALLSET_32
	c = (result >> 32) & MASK_ALLSET_32
	d = result & MASK_ALLSET_32
	return rt + "[128b] = (" + ra + " >> {:d}) & 0x{:08X}:{:08X}:{:08X}:{:08X}".format(shift,a,b,c,d)

# Right shift 4x32 by bit
def rotmi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x3F
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a      = MASK_ALLSET_32 >> shift
	return rt + "[4x32b] = (" + ra + " >> {:d}) & 0x{:08X}".format(shift,a)

# Right shift 8x16 by bit
def rothmi(opcode):
	shift  = (0 -(opcode >> 14)) & 0x1F
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a      = MASK_ALLSET_16 >> shift
	return rt + "[8x16b] = (" + ra + " >> {:d}) & 0x{:04X}".format(shift,a)

# Left rotate 128 by bit
def rotqbii(opcode):
	shift  = (opcode >> 14) & 0x7
	const  = MASK_ALLSET_128
	result1 = const << shift
	result2 = const >> (128-shift)
	result1 &= MASK_ALLSET_128
	result2 &= MASK_ALLSET_128
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	# fixme: maybe split in 4 rows? Ugly
	return rt + "[128b] = (" + ra + " << {:d}) & 0x{:032X} | (".format(shift,result1) + ra + " >> {:d}) & 0x{:032X}".format((128-shift),result2)

# Left rotate 128 by byte
def rotqbyi(opcode):
	shift  = (opcode >> 14) & 0xF
	shift  *= 8
	const  = 0xAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD
	result = const << shift | const >>( 128-shift)
	result &= MASK_ALLSET_128
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	a = (result >> 96) & MASK_ALLSET_32
	b = (result >> 64) & MASK_ALLSET_32
	c = (result >> 32) & MASK_ALLSET_32
	d = result & MASK_ALLSET_32
	return rt + "[128b] = " + ra + " : {:08X}:{:08X}:{:08X}:{:08X}".format(a,b,c,d)

# Left rotate 4x32 by bit
def roti(opcode):
	#fixme: shift is signed?
	shift  = (opcode >> 14) & 0x1F
	result1 = MASK_ALLSET_32 << shift
	result2 = MASK_ALLSET_32 >> (32-shift)
	result1 &= MASK_ALLSET_32
	result2 &= MASK_ALLSET_32
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = (" + ra + " << {:d}) & 0x{:08X} | (".format(shift,result1) + ra + " >> {:d}) & 0x{:08X}".format((32-shift),result2)

# Left rotate 8x16 by bit
def rothi(opcode):
	shift  = (opcode >> 14) & 0xF
	result1 = MASK_ALLSET_16 << shift
	result2 = MASK_ALLSET_16 >> (16-shift)
	result1 &= MASK_ALLSET_16
	result2 &= MASK_ALLSET_16
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	# we can have special case here:
	if shift == 8:
		return rt + "[8x16b] = byteswap16(" + ra + ")"
	return rt + "[8x16b] = (" + ra + " << {:d}) & 0x{:04X} | (".format(shift,result1) + ra + " >> {:d}) & 0x{:04X}".format((16-shift),result2)

#########################
# Non imm rotate start: #
#########################

# Right arithm shift 4x32 by bit from rb
def rotma(opcode):
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = " + ra + " >> -(" + rb + ") & 0x3F"

# Right arithm shift 8x16 by bit from rb
def rotmah(opcode):
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[8x16b] = " + ra + " >> -(" + rb + ") & 0x1F"

# Right shift 128 by bit from rb
def rotqmbi(opcode):
	rb     = get_preferred_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[128b] = " + ra + " >> -(" + rb + ") & 7"

# Right shift 128 by byte from rb
def rotqmbybi(opcode):
	rb     = get_preferred_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[128b] = " + ra + " >> ( -(" + rb + " >> 3) & 0x1F) * 8"

# Right shift 128 by byte from rb
def rotqmby(opcode):
	rb     = get_preferred_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[128b] = " + ra + " >> ( -(" + rb + ") & 0x1F) * 8"

# Right logical shift 4x32 by bit from rb
def rotm(opcode):
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = " + ra + " >> -(" + rb + ") & 0x3F"

# Right logical shift 8x16 by bit from rb
def rothm(opcode):
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[8x16b] = " + ra + " >> -(" + rb + ") & 0x1F"

# Left rotate 128 by bit from rb
def rotqbi(opcode):
	rb     = get_preferred_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[128b] = " + ra + " << (" + rb + " & 7) | " + ra + " >> 128 - (" + rb + " & 7)"

#fixme wtf
def rotqbybi(opcode):
	rb     = get_preferred_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[128b] = " + ra + " << ((" + rb + " >> 3) & 0xF) * 8 | " + ra + " >> 128 - (((" + rb + " >> 3) & 0xF) * 8)"


# Left rotate 128 by byte from rb
def rotqby(opcode):
	rb     = get_preferred_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[128b] = " + ra + " << (" + rb + " & 0xF) * 8 | " + ra + " >> 128 - ((" + rb + " & 0xF) * 8)"

# Left rotate 4x32 by bit from rb
def rot(opcode):
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[4x32b] = " + ra + " << (" + rb + " & 0x1F) | " + ra + " >> 32 - (" + rb + " & 0x1F)"

# Left rotate 8x16 by bit from rb
def roth(opcode):
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt + "[8x16b] = " + ra + " << (" + rb + " & 0xF) | " + ra + " >> 16 - (" + rb + " & 0xF)"

###################
# Branches start: #
###################

# Warning! Code for branches assume that SPU program is PS3 version.
# This mean address is AND with 0x3FFFC.
# This should be changed if you are working with hardware different than PS3.

# Branch indirect (always)
def bi(opcode):
	ra     = get_preferred_reg((opcode >> 7) & 0x7F)
	return "PC = " + ra + " & 0x3FFFC"

# Branch indirect and link if external data
def bisled(addr, opcode):
	ra     = get_preferred_reg((opcode >> 7) & 0x7F)
	rt     = get_preferred_reg(opcode & 0x7F)
	return "if ext_data: PC = " + ra + "& 0x3FFFC, ", + rt + " = 0x{:05X}".format(addr + 4)

# Branch indirect and set link (always)
def bisl(addr, opcode):
	ra     = get_preferred_reg((opcode >> 7) & 0x7F)
	rt     = get_preferred_reg(opcode & 0x7F)
	return "PC = " + ra + " & 0x3FFFC, " + rt + " = 0x{:05X}".format(addr + 4)

# Branch indirect if zero
def biz(addr, opcode):
	ra     = get_preferred_reg((opcode >> 7) & 0x7F)
	rt     = get_preferred_reg(opcode & 0x7F)
	return "if " + rt + " == 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

# Branch indirect if not zero
def binz(addr, opcode):
	ra     = get_preferred_reg((opcode >> 7) & 0x7F)
	rt     = get_preferred_reg(opcode & 0x7F)
	return "if " + rt + " != 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

# Branch indirect if zero halfword
def bihz(addr, opcode):
	ra     = get_preferred_reg((opcode >> 7) & 0x7F)
	rt     = get_preferred_reg(opcode & 0x7F)
	return "if (" + rt + "[32b] & 0xFFFF) == 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

# Branch indirect if not zero halfword
def bihnz(addr, opcode):
	ra     = get_preferred_reg((opcode >> 7) & 0x7F)
	rt     = get_preferred_reg(opcode & 0x7F)
	return "if (" + rt + "[32b] & 0xFFFF) != 0: PC = " + ra + " & 0x3FFFC, else: PC = 0x{:05X}".format(addr + 4)

###################
# Compares start: #
###################

# Compare Equal Byte
def ceqb(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[16x8b] if " + ra + " == " + rb + ": " + rt + " = 0xFF, else 0x00"
# Compare Equal Halfword
def ceqh(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[8x16b] if " + ra + " == " + rb + ": " + rt + " = 0xFFFF, else 0x0000"

# Compare Equal Word
def ceq(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[4x32b] if " + ra + " == " + rb + ": " + rt + " = 0xFFFFFFFF, else 0x00000000"

# Compare Greater Than Byte
def cgtb(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[16x8b][signed] if " + ra + " > " + rb + ": " + rt + " = 0xFF, else 0x00"

# Compare Greater Than Halfword
def cgth(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[8x16b][signed] if " + ra + " > " + rb + ": " + rt + " = 0xFFFF, else 0x0000"

# Compare Greater Than Word
def cgt(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[4x32b][signed] if " + ra + " > " + rb + ": " + rt + " = 0xFFFFFFFF, else 0x00000000"

def clgtb(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[16x8b][unsigned] if " + ra + " > " + rb + ": " + rt + " = 0xFF, else 0x00"

def clgth(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[8x16b][unsigned] if " + ra + " > " + rb + ": " + rt + " = 0xFFFF, else 0x0000"

def clgt(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return "[4x32b][unsigned] if " + ra + " > " + rb + ": " + rt + " = 0xFFFFFFFF, else 0x00000000"

def ceqbi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0xFF
	return "[16x8b] if " + ra + " == 0x{:X}: ".format(imm) + rt + " = 0xFF, else 0x00"

def ceqhi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0xFF
	imm    = sign_extend_imm10(1, imm)
	return "[8x16b] if " + ra + " == 0x{:X}: ".format(imm) + rt + " = 0xFFFF, else 0x0000"

def ceqi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0xFF
	imm    = sign_extend_imm10(0, imm)
	return "[4x32b] if " + ra + " == 0x{:X}: ".format(imm) + rt + " = 0xFFFFFFFF, else 0x00000000"

def cgtbi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0xFF
	sign   = ""
	if (imm > 0x7F):
		imm = ~imm
		imm &= 0x7F
		imm += 1
		sign = "-"
	imm   = sign + "0x{:X}".format(imm)
	return "[16x8b][signed] if " + ra + " > " + imm + ": " + rt + " = 0xFF, else 0x00"

def cgthi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return "[8x16b][signed] if " + ra + " > " + imm + ": " + rt + " = 0xFFFF, else 0x0000"

def cgti(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0x3FF
	imm    = imm10_to_signed_string(imm)
	return "[4x32b][signed] if " + ra + " > " + imm + ": " + rt + " = 0xFFFFFFFF, else 0x00000000"

def clgtbi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0xFF
	return "[16x8b][unsigned] if " + ra + " > 0x{:X}: ".format(imm) + rt + " = 0xFF, else 0x00"

def clgthi(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0xFF
	imm    = sign_extend_imm10(1, imm)
	return "[8x16b][unsigned] if " + ra + " > 0x{:X}: ".format(imm) + rt + " = 0xFFFF, else 0x0000"

def clgti(opcode):

	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	imm    = (opcode >> 14) & 0xFF
	imm    = sign_extend_imm10(0, imm)
	return "[4x32b][unsigned] if " + ra + " > 0x{:X}: ".format(imm) + rt + " = 0xFFFFFFFF, else 0x00000000"

######################
# Channel r/w start: #
######################

def wrch(opcode):

	ca     = get_channel((opcode >> 7) & 0x7F)
	cc     = (opcode >> 7) & 0x7F
	rt     = get_preferred_reg(opcode & 0x7F)
	return ca + "[32b](ch{:d}) = ".format(cc) + rt

# fixme: 96 bits zeroed
def rdch(opcode):

	ca     = get_channel((opcode >> 7) & 0x7F)
	cc     = (opcode >> 7) & 0x7F
	rt     = get_preferred_reg(opcode & 0x7F)
	return rt + " = " + ca + "[32b](ch{:d})".format(cc)

def rchcnt(opcode):

	ca     = get_channel((opcode >> 7) & 0x7F)
	cc     = (opcode >> 7) & 0x7F
	rt     = get_preferred_reg(opcode & 0x7F)
	return rt + " = chnnel count of " + ca + " (ch{:d})".format(cc)

###############
# Misc start: #
###############

def shufb(addr, opcode):

	rt     = get_reg((opcode >> 21) & 0x7F)
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rc     = get_reg(opcode & 0x7F)
	cmt    = ".\nfor (field = 0; field <= 15; field++)\n{\n\tx = " + rc + ".byte[field]\n\tif (x < 0x80)\n\t{\n\t    if      (x & 0x10) == 0x00) {" + rt + ".byte[field] = " + ra + ".byte[x & 0x0f];}\n\t    else if (x & 0x10) == 0x10) {" + rt + ".byte[field] = " + rb + ".byte[x & 0x0f];}\n\t}\n\telse\n\t{\n\t    if      (x >= 0x80 && x < 0xC0) {" + rt + ".byte[field] = 0x00;}\n\t    else if (x >= 0xC0 && x < 0xE0) {" + rt + ".byte[field] = 0xFF;}\n\t    else if (x >= 0xE0)             {" + rt + ".byte[field] = 0x80;}\n\t}\n}"
	cmt2   = "Are you sure you want to place this comment?\nfor (field = 0; field <= 15; field++)\n{\n    x = " + rc + ".byte[field]\n    if (x < 0x80)\n    {\n        if      (x & 0x10) == 0x00) {" + rt + ".byte[field] = " + ra + ".byte[x & 0x0f];}\n        else if (x & 0x10) == 0x10) {" + rt + ".byte[field] = " + rb + ".byte[x & 0x0f];}\n    }\n    else\n    {\n        if      (x >= 0x80 && x < 0xC0) {" + rt + ".byte[field] = 0x00;}\n        else if (x >= 0xC0 && x < 0xE0) {" + rt + ".byte[field] = 0xFF;}\n        else if (x >= 0xE0)             {" + rt + ".byte[field] = 0x80;}\n    }\n}"
	cmt3   = shufb_patterns(addr - 4, opcode)
	if cmt3 == 0:
		answer = ask_yn(0, cmt2)
		if answer < 1:
			return 1
		return cmt
	return cmt3

def selb(opcode):

	rt     = get_reg((opcode >> 21) & 0x7F)
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rc     = get_reg(opcode & 0x7F)
	return rt + "[16x8b] = " + rc + " & " + rb + " | ~" + rc + " & " + ra + " (if bit in " + rc + " is 1 take bit from " + rb + ", else from " + ra + ")"

def fa(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4xfloat] = " + ra + " + " + rb

def fs(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4xfloat] = " + ra + " - " + rb

def fm(opcode):

	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	return rt +"[4xfloat] = " + ra + " * " + rb

def fma(opcode):

	rt     = get_reg((opcode >> 21) & 0x7F)
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rc     = get_reg(opcode & 0x7F)
	return rt +"[4xfloat] = (" + ra + " * " + rb + ") + " + rc

def fnms(opcode):

	rt     = get_reg((opcode >> 21) & 0x7F)
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rc     = get_reg(opcode & 0x7F)
	return rt +"[4xfloat] = " + rc + " - (" + ra + " * " + rb + ")"

def fms(opcode):

	rt     = get_reg((opcode >> 21) & 0x7F)
	rb     = get_reg((opcode >> 14) & 0x7F)
	ra     = get_reg((opcode >> 7) & 0x7F)
	rc     = get_reg(opcode & 0x7F)
	return rt +"[4xfloat] = (" + ra + " * " + rb + ") - " + rc

def csflt(opcode):

	scale  = (opcode >> 14) & 0xFF
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	scale  = numpy.exp2(155 - scale)
	return rt +"[4xfloat] = (float)(s32)" + ra + " / {:.1f}".format(scale)

def cuflt(opcode):

	scale  = (opcode >> 14) & 0xFF
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	scale  = numpy.exp2(155 - scale)
	return rt +"[4xfloat] = (float)(u32)" + ra + " / {:.1f}".format(scale)

def cflts(opcode):

	scale  = (opcode >> 14) & 0xFF
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	scale  = numpy.exp2(173 - scale)
	return rt +"[4x32b] = (s32)((float)" + ra + " * {:.1f})".format(scale)

def cfltu(opcode):

	scale  = (opcode >> 14) & 0xFF
	ra     = get_reg((opcode >> 7) & 0x7F)
	rt     = get_reg(opcode & 0x7F)
	scale  = numpy.exp2(173 - scale)
	return rt +"[4x32b] = (u32)((float)" + ra + " * {:.1f})".format(scale)


# Todo:
# non imm shifts, Floating Reciprocal Estimate, frsqest, fi, 
# else: simplify x by 0

def SPUAsm2C(addr):

	opcode = get_wide_dword(addr)
	opcode_name = print_insn_mnem(addr)
	if   opcode_name == "fsmbi": return fsmbi(opcode)
	elif opcode_name == "avgb": return avgb(opcode)
	elif opcode_name == "absdb": return absdb(opcode)
	elif opcode_name == "andc": return andc(opcode)
	elif opcode_name == "andbi": return andbi(opcode)
	elif opcode_name == "andhi": return andhi(opcode)
	elif opcode_name == "andi": return andi(opcode)
	elif opcode_name == "orc": return orc(opcode)
	elif opcode_name == "orbi": return orbi(opcode)
	elif opcode_name == "orhi": return orhi(opcode)
	elif opcode_name == "ori": return ori(opcode)
	elif opcode_name == "orx": return orx(opcode)
	elif opcode_name == "xorbi": return xorbi(opcode)
	elif opcode_name == "xorhi": return xorhi(opcode)
	elif opcode_name == "xori": return xori(opcode)
	elif opcode_name == "eqv": return eqv(opcode)
	elif opcode_name == "ilh": return ilh(opcode)
	elif opcode_name == "ilhu": return ilhu(opcode)
	elif opcode_name == "il": return il(opcode)
	elif opcode_name == "ila": return ila(opcode)
	elif opcode_name == "iohl": return iohl(opcode)
	elif opcode_name == "ah": return ah(opcode)
	elif opcode_name == "a": return a(opcode)
	elif opcode_name == "addx": return addx(opcode)
	elif opcode_name == "sfh": return sfh(opcode)
	elif opcode_name == "sf": return sf(opcode)
	elif opcode_name == "sfx": return sfx(opcode)
	elif opcode_name == "ahi": return ahi(opcode)
	elif opcode_name == "ai": return ai(opcode)
	elif opcode_name == "sfhi": return sfhi(opcode)
	elif opcode_name == "sfi": return sfi(opcode)
	elif opcode_name == "bg": return bg(opcode)
	elif opcode_name == "mpy": return mpy(opcode)
	elif opcode_name == "mpyu": return mpyu(opcode)
	elif opcode_name == "mpya": return mpya(opcode)
	elif opcode_name == "mpyh": return mpyh(opcode)
	elif opcode_name == "mpys": return mpys(opcode)
	elif opcode_name == "mpyhh": return mpyhh(opcode)
	elif opcode_name == "mpyhha": return mpyhha(opcode)
	elif opcode_name == "mpyhhu": return mpyhhu(opcode)
	elif opcode_name == "mpyhhau": return mpyhhau(opcode)
	elif opcode_name == "mpyi": return mpyi(opcode)
	elif opcode_name == "mpyui": return mpyui(opcode)
	elif opcode_name == "shlqbyi": return shlqbyi(opcode)
	elif opcode_name == "shlqbii": return shlqbii(opcode)
	elif opcode_name == "shli": return shli(opcode)
	elif opcode_name == "shlhi": return shlhi(opcode)
	elif opcode_name == "rotmai": return rotmai(opcode)
	elif opcode_name == "rotmahi": return rotmahi(opcode)
	elif opcode_name == "rotqmbii": return rotqmbii(opcode)
	elif opcode_name == "rotqmbyi": return rotqmbyi(opcode)
	elif opcode_name == "rotmi": return rotmi(opcode)
	elif opcode_name == "rothmi": return rothmi(opcode)
	elif opcode_name == "rotqbii": return rotqbii(opcode)
	elif opcode_name == "rotqbyi": return rotqbyi(opcode)
	elif opcode_name == "roti": return roti(opcode)
	elif opcode_name == "rothi": return rothi(opcode)
	elif opcode_name == "rotma": return rotma(opcode)
	elif opcode_name == "rotmah": return rotmah(opcode)
	elif opcode_name == "rotqmbi": return rotqmbi(opcode)
	elif opcode_name == "rotqmbybi": return rotqmbybi(opcode)
	elif opcode_name == "rotqmby": return rotqmby(opcode)
	elif opcode_name == "rotm": return rotm(opcode)
	elif opcode_name == "rothm": return rothm(opcode)
	elif opcode_name == "rotqbi": return rotqbi(opcode)
	elif opcode_name == "rotqby": return rotqby(opcode)
	elif opcode_name == "rot": return rot(opcode)
	elif opcode_name == "roth": return roth(opcode)
	elif opcode_name == "bi": return bi(opcode)
	elif opcode_name == "bisled": return bisled(addr, opcode)
	elif opcode_name == "bisl": return bisl(addr, opcode)
	elif opcode_name == "biz": return biz(addr, opcode)
	elif opcode_name == "binz": return binz(addr, opcode)
	elif opcode_name == "bihz": return bihz(addr, opcode)
	elif opcode_name == "bihnz": return bihnz(addr, opcode)
	elif opcode_name == "xsbh": return xsbh(opcode)
	elif opcode_name == "xshw": return xshw(opcode)
	elif opcode_name == "xswd": return xswd(opcode)
	elif opcode_name == "shufb": return shufb(addr, opcode)
	elif opcode_name == "selb": return selb(opcode)
	elif opcode_name == "wrch": return wrch(opcode)
	elif opcode_name == "rdch": return rdch(opcode)
	elif opcode_name == "rchcnt": return rchcnt(opcode)
	elif opcode_name == "ceqb": return ceqb(opcode)
	elif opcode_name == "ceqh": return ceqh(opcode)
	elif opcode_name == "ceq": return ceq(opcode)
	elif opcode_name == "cgtb": return cgtb(opcode)
	elif opcode_name == "cgth": return cgth(opcode)
	elif opcode_name == "cgt": return cgt(opcode)
	elif opcode_name == "clgtb": return clgtb(opcode)
	elif opcode_name == "clgth": return clgth(opcode)
	elif opcode_name == "clgt": return clgt(opcode)
	elif opcode_name == "ceqbi": return ceqbi(opcode)
	elif opcode_name == "ceqhi": return ceqhi(opcode)
	elif opcode_name == "ceqi": return ceqi(opcode)
	elif opcode_name == "cgtbi": return cgtbi(opcode)
	elif opcode_name == "cgthi": return cgthi(opcode)
	elif opcode_name == "cgti": return cgti(opcode)
	elif opcode_name == "clgtbi": return clgtbi(opcode)
	elif opcode_name == "clgthi": return clgthi(opcode)
	elif opcode_name == "clgti": return clgti(opcode)
	# fpu
	elif opcode_name == "fa": return fa(opcode)
	elif opcode_name == "fs": return fs(opcode)
	elif opcode_name == "fm": return fm(opcode)
	elif opcode_name == "fma": return fma(opcode)
	elif opcode_name == "fnms": return fnms(opcode)
	elif opcode_name == "fms": return fms(opcode)
	# need numpy
	elif opcode_name == "csflt" and FLT_CONVERSION_SUPPORT == 1: return csflt(opcode)
	elif opcode_name == "cuflt" and FLT_CONVERSION_SUPPORT == 1: return cuflt(opcode)
	elif opcode_name == "cflts" and FLT_CONVERSION_SUPPORT == 1: return cflts(opcode)
	elif opcode_name == "cfltu" and FLT_CONVERSION_SUPPORT == 1: return cfltu(opcode)

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
