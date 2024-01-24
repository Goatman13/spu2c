# spu2c
CELL SPU to C plugin for IDA

Features
-------

- Plugin create easy to understand C style comments for SPU opcodes.
- Every comment state size of operation [128b], [8x16b], and [4x32b].
- While opcode name is read from text, opcode fields are read from hex to mitigate few IDA spu plugin bugs.
- Easy to install, just throw into IDA plugins directory, and restart IDA.

 To scan single opcode push F10.
 To scan multiple opcodes, mark them with mouse, and push F10.
 To scan whole function, select any address inside function and press ALT + SHIFT + F10.

Examples
--------

    fsmbi  r82, 0x3333       # r82[128b] = 0x0000FFFF:0000FFFF:0000FFFF:0000FFFF
    fsmbi  r83, 0xF000       # r83[128b] = 0xFFFFFFFF:00000000:00000000:00000000
    shlqbyi  r66, r69, 3     # r66[128b] = (r69 << 24) & 0xFFFFFFFF:FFFFFFFF:FFFFFFFF:FF000000
    rotqby  r16, r17, r7     # r16[128b] = r17 << ((r7 & 0xF) * 8) | r17 >> (128 - ((r7 & 0xF) * 8))
    rotqmbii  r10, r10, -1   # r10[128b] = (r10 >> 1) & 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    rotqmbyi  r12, r34, -0xC # r12[128b] = (r34 >> 96) & 0x000000000000000000000000FFFFFFFF
    rotqmby  r11, r10, r12   # r11[128b] = r10 >> (( -(r12) & 0x1F) * 8)
    rotmi  r3, r12, -24      # r3[4x32b] = (r12 >> 24) & 0x000000FF
    shli  r43, r79, 0x1D     # r43[4x32b] = (r79 << 29) & 0xE0000000
    shlhi  r12, r12, 2       # r12[8x16b] = (r12 << 2) & 0xFFFC
    roti  r5, r10, 0xF       # r5[4x32b] = (r10 << 15) & 0xFFFF8000 | (r10 >> 17) & 0x00007FFF
    rot  r21, r41, r42       # r21[4x32b] = r41 << (r42 & 0x1F) | r41 >> (32 - (r42 & 0x1F))
    
	ABCD = 4x32 bit slots of source register
    rotqbyi  r79, r7, 0xD    # r79[128b] = r7 : DDDDDDAAAAAAAABBBBBBBBCCCCCCCCDD
    rotqbyi  r54, r7, 8      # r54[128b] = r7 : CCCCCCCCDDDDDDDDAAAAAAAABBBBBBBB
