/*
    fenris - program execution path analysis tool
    ---------------------------------------------

    Copyright (C) 2001, 2002 by Bindview Corporation
    Portions copyright (C) 2001, 2002 by their respective contributors
    Developed and maintained by Michal Zalewski <lcamtuf@coredump.cx>

    Portions of this code are based on libi386 library from 'bastard' project
    developed by mammon and few other guys. Please visit their webpage,
    http://bastard.sourceforge.net to learn more about this very interesting
    project.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "i386.h"

#define AS_UINT(x)   (*((unsigned int*)&(x)))
#define AS_USHORT(x) (*((unsigned short int*)&(x)))

struct addr_exp  expr;
struct EXT__ARCH *settings;

asmtable tables86[]={
    {tbl_Main,0x00,0x00,0,0xff,0,0xff,1},             /* 0 */
    {tbl_0F,0x0f,0x00,1,0xff,0,0xff,1},
    {tbl_80,0x80,0x00,1,0x07,0,0xff,8},
    {tbl_81,0x81,0x00,1,0x07,0,0xff,8},
    {tbl_82,0x82,0x00,1,0x07,0,0xff,8},
    {tbl_83,0x83,0x00,1,0x07,0,0xff,8},               /* 5 */
    {tbl_C0,0xc0,0x00,1,0x07,0,0xff,8},
    {tbl_C1,0xc1,0x00,1,0x07,0,0xff,8},
    {tbl_D0,0xd0,0x00,1,0x07,0,0xff,8},
    {tbl_D1,0xd1,0x00,1,0x07,0,0xff,8},
    {tbl_D2,0xd2,0x00,1,0x07,0,0xff,8},               /* 10 */
    {tbl_D3,0xd3,0x00,1,0x07,0,0xff,8},
    {tbl_F6,0xf6,0x00,1,0x07,0,0xff,8},
    {tbl_F7,0xf7,0x00,1,0x07,0,0xff,8},
    {tbl_FE,0xfe,0x00,1,0x07,0,0xff,8},
    {tbl_FF,0xff,0x00,1,0x07,0,0xff,8},               /* 15 */
    {tbl_0F00,0x0f,0x00,2,0x07,0,0xff,8},
    {tbl_0F01,0x0f,0x01,2,0x07,0,0xff,8},
    {tbl_0F18,0x0f,0x18,2,0x07,0,0xff,8},
    {tbl_0F71,0x0f,0x71,2,0x07,0,0xff,8},
    {tbl_0F72,0x0f,0x72,2,0x07,0,0xff,8},      /* 20 */
    {tbl_0F73,0x0f,0x73,2,0x07,0,0xff,8},
    {tbl_0FAE,0x0f,0xae,2,0x07,0,0xff,8},
    {tbl_0FBA,0x0f,0xba,2,0x07,0,0xff,8},
    {tbl_0FC7,0x0f,0xc7,2,0x07,0,0xff,8}      /* 25 */
};

int prefix_table[][2] = {
    { 0xF0, PREFIX_LOCK},
    { 0xF2, PREFIX_REPNZ},
    { 0xF3, PREFIX_REP},
    { 0x2E, PREFIX_CS},
    { 0x36, PREFIX_SS},
    { 0x3E, PREFIX_DS},
    { 0x26, PREFIX_ES},
    { 0x64, PREFIX_FS},
    { 0x65, PREFIX_GS},
    { 0x66, PREFIX_OP_SIZE},
    { 0x67, PREFIX_ADDR_SIZE},
//  { 0x0F, PREFIX_SIMD},
    { 0,    0}
};

char *reg_dword[]   = {"eax",   "ecx",   "edx",   "ebx",   "esp",   "ebp",   "esi",   "edi"   };
char *reg_word[]    = {"ax",    "cx",    "dx",    "bx",    "sp",    "bp",    "si",    "di"    };
char *reg_byte[]    = {"al",    "cl",    "dl",    "bl",    "ah",    "ch",    "dh",    "bh"    };
char *reg_mmx[]     = {"mm0",   "mm1",   "mm2",   "mm3",   "mm4",   "mm5",   "mm6",   "mm7"   };
char *reg_simd[]    = {"xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7"  };
char *reg_debug[]   = {"dr0",   "dr1",   "dr2",   "dr3",   "dr4",   "dr5",   "dr6",   "dr7"   };
char *reg_control[] = {"cr0",   "cr1",   "cr2",   "cr3",   "cr4",   "cr5",   "cr6",   "cr7"   };
char *reg_test[]    = {"tr0",   "tr1",   "tr2",   "tr3",   "tr4",   "tr5",   "tr6",   "tr7"   };
char *reg_seg[]     = {"es",    "cs",    "ss",    "ds",    "fs",    "gs",    "",      ""      };
char *reg_fpu[]     = {"st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)" };

int modrm_rm[]  = {0, 1, 2, 3, MODRM_RM_SIB, MODRM_MOD_DISP32, 6, 7 };
int modrm_reg[] = {0, 1, 2, 3, 4, 5, 6, 7 };
int modrm_mod[] = {0, MODRM_MOD_DISP8, MODRM_MOD_DISP32, MODRM_MOD_NOEA };

int sib_scl[] = {0, 2, 4, 8};
int sib_idx[] = {0, 1, 2, 3, SIB_INDEX_NONE, 5, 6, 7 };
int sib_bas[] = {0, 1, 2, 3, 4, SIB_SCALE_NOBASE, 6, 7 };

instr tbl_Main[] = {
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "add",    0,                  0,                  0}, /* 0x0  */
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "add",    0,                  0,                  0}, /* 0x1  */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "add",    0,                  0,                  0}, /* 0x2  */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "add",    0,                  0,                  0}, /* 0x3  */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "add",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0x4  */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "add",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x5  */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   0+REG_SEG_OFFSET,   0,                  0}, /* 0x6  */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    0+REG_SEG_OFFSET,   0,                  0}, /* 0x7  */
    { 0,  INS_LOGIC,                     ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "or",     0,                  0,                  0}, /* 0x8  */
    { 0,  INS_LOGIC,                     ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "or",     0,                  0,                  0}, /* 0x9  */
    { 0,  INS_LOGIC,                     ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "or",     0,                  0,                  0}, /* 0xA  */
    { 0,  INS_LOGIC,                     ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "or",     0,                  0,                  0}, /* 0xB  */
    { 0,  INS_LOGIC,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "or",     0+REG_BYTE_OFFSET,  0,                  0}, /* 0xC  */
    { 0,  INS_LOGIC,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "or",     0+REG_DWORD_OFFSET, 0,                  0}, /* 0xD  */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   1+REG_SEG_OFFSET,   0,                  0}, /* 0xE  */
    { 1,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xF  */
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "adc",    0,                  0,                  0}, /* 0x10 */
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "adc",    0,                  0,                  0}, /* 0x11 */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "adc",    0,                  0,                  0}, /* 0x12 */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "adc",    0,                  0,                  0}, /* 0x13 */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "adc",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0x14 */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "adc",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x15 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   2+REG_SEG_OFFSET,   0,                  0}, /* 0x16 */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    2+REG_SEG_OFFSET,   0,                  0}, /* 0x17 */
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "sbb",    0,                  0,                  0}, /* 0x18 */
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "sbb",    0,                  0,                  0}, /* 0x19 */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "sbb",    0,                  0,                  0}, /* 0x1A */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "sbb",    0,                  0,                  0}, /* 0x1B */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "sbb",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0x1C */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "sbb",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x1D */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   3+REG_SEG_OFFSET,   0,                  0}, /* 0x1E */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    3+REG_SEG_OFFSET,   0,                  0}, /* 0x1F */
    { 0,  INS_LOGIC,                     ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "and",    0,                  0,                  0}, /* 0x20 */
    { 0,  INS_LOGIC,                     ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "and",    0,                  0,                  0}, /* 0x21 */
    { 0,  INS_LOGIC,                     ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_d|OP_R, ARG_NONE,        cpu_80386, "and",    0,                  0,                  0}, /* 0x22 */
    { 0,  INS_LOGIC,                     ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "and",    0,                  0,                  0}, /* 0x23 */
    { 0,  INS_LOGIC,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "and",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0x24 */
    { 0,  INS_LOGIC,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "and",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x25 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x26 */
    { 0,  INS_ARITH,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "daa",    0,                  0,                  0}, /* 0x27 */
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "sub",    0,                  0,                  0}, /* 0x28 */
    { 0,  INS_ARITH,                     ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "sub",    0,                  0,                  0}, /* 0x29 */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "sub",    0,                  0,                  0}, /* 0x2A */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "sub",    0,                  0,                  0}, /* 0x2B */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "sub",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0x2C */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "sub",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x2D */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x2E */
    { 0,  INS_ARITH,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "das",    0,                  0,                  0}, /* 0x2F */
    { 0,  INS_LOGIC,                     ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "xor",    0,                  0,                  0}, /* 0x30 */
    { 0,  INS_LOGIC,                     ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "xor",    0,                  0,                  0}, /* 0x31 */
    { 0,  INS_LOGIC,                     ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "xor",    0,                  0,                  0}, /* 0x32 */
    { 0,  INS_LOGIC,                     ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "xor",    0,                  0,                  0}, /* 0x33 */
    { 0,  INS_LOGIC,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "xor",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0x34 */
    { 0,  INS_LOGIC,                     OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "xor",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x35 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x36 */
    { 0,  INS_ARITH,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "aaa",    0,                  0,                  0}, /* 0x37 */
    { 0,  INS_FLAG,                      ADDRMETH_E|OPTYPE_b|OP_R, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "cmp",    0,                  0,                  0}, /* 0x38 */
    { 0,  INS_FLAG,                      ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "cmp",    0,                  0,                  0}, /* 0x39 */
    { 0,  INS_FLAG,                      ADDRMETH_G|OPTYPE_b|OP_R, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "cmp",    0,                  0,                  0}, /* 0x3A */
    { 0,  INS_FLAG,                      ADDRMETH_G|OPTYPE_v|OP_R, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "cmp",    0,                  0,                  0}, /* 0x3B */
    { 0,  INS_FLAG,                      OP_REG|OP_R,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "cmp",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0x3C */
    { 0,  INS_FLAG,                      OP_REG|OP_R,              ADDRMETH_I|OPTYPE_d|OP_R, ARG_NONE,        cpu_80386, "cmp",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x3D */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x3E */
    { 0,  INS_ARITH,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "aas",    0,                  0,                  0}, /* 0x3F */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x40 */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    1+REG_DWORD_OFFSET, 0,                  0}, /* 0x41 */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    2+REG_DWORD_OFFSET, 0,                  0}, /* 0x42 */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    3+REG_DWORD_OFFSET, 0,                  0}, /* 0x43 */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    4+REG_DWORD_OFFSET, 0,                  0}, /* 0x44 */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    5+REG_DWORD_OFFSET, 0,                  0}, /* 0x45 */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    6+REG_DWORD_OFFSET, 0,                  0}, /* 0x46 */
    { 0,  INS_ARITH,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "inc",    7+REG_DWORD_OFFSET, 0,                  0}, /* 0x47 */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x48 */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    1+REG_DWORD_OFFSET, 0,                  0}, /* 0x49 */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    2+REG_DWORD_OFFSET, 0,                  0}, /* 0x4A */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    3+REG_DWORD_OFFSET, 0,                  0}, /* 0x4B */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    4+REG_DWORD_OFFSET, 0,                  0}, /* 0x4C */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    5+REG_DWORD_OFFSET, 0,                  0}, /* 0x4D */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    6+REG_DWORD_OFFSET, 0,                  0}, /* 0x4E */
    { 0,  INS_ARITH,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "dec",    7+REG_DWORD_OFFSET, 0,                  0}, /* 0x4F */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   0+REG_DWORD_OFFSET, 0,                  0}, /* 0x50 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   1+REG_DWORD_OFFSET, 0,                  0}, /* 0x51 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   2+REG_DWORD_OFFSET, 0,                  0}, /* 0x52 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   3+REG_DWORD_OFFSET, 0,                  0}, /* 0x53 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   4+REG_DWORD_OFFSET, 0,                  0}, /* 0x54 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   5+REG_DWORD_OFFSET, 0,                  0}, /* 0x55 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   6+REG_DWORD_OFFSET, 0,                  0}, /* 0x56 */
    { 0,  INS_STACK,                     OP_REG|OP_R,              ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   7+REG_DWORD_OFFSET, 0,                  0}, /* 0x57 */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0x58 */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    1+REG_DWORD_OFFSET, 0,                  0}, /* 0x59 */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    2+REG_DWORD_OFFSET, 0,                  0}, /* 0x5A */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    3+REG_DWORD_OFFSET, 0,                  0}, /* 0x5B */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    4+REG_DWORD_OFFSET, 0,                  0}, /* 0x5C */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    5+REG_DWORD_OFFSET, 0,                  0}, /* 0x5D */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    6+REG_DWORD_OFFSET, 0,                  0}, /* 0x5E */
    { 0,  INS_STACK,                     OP_REG|OP_W,              ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    7+REG_DWORD_OFFSET, 0,                  0}, /* 0x5F */
    { 0,  INS_STACK,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "pushad", 0,                  0,                  0}, /* 0x60 */
    { 0,  INS_STACK,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "popad",  0,                  0,                  0}, /* 0x61 */
    { 0,  INS_ARRAY,                     ADDRMETH_G|OPTYPE_v|OP_R, ADDRMETH_M|OPTYPE_a|OP_R, ARG_NONE,        cpu_80386, "bound",  0,                  0,                  0}, /* 0x62 */
    { 0,  INS_SYSTEM,                    ADDRMETH_E|OPTYPE_w|OP_R, ADDRMETH_G|OPTYPE_w|OP_R, ARG_NONE,        cpu_80386, "arpl",   0,                  0,                  0}, /* 0x63 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x64 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x65 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x66 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x67 */
    { 0,  INS_STACK,                     ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   0,                  0,                  0}, /* 0x68 */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_v|OP_R, ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OP_R, cpu_80386, "imul",   0,                  0,                  0}, /* 0x69 */
    { 0,  INS_STACK,                     ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,                 ARG_NONE,        cpu_80386, "push",   0,                  0,                  0}, /* 0x6A */
    { 0,  INS_ARITH,                     ADDRMETH_G|OPTYPE_v|OP_R, ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OP_R, cpu_80386, "imul",   0,                  0,                  0}, /* 0x6B */
    { 0,  INS_MOVE|INS_SYSTEM|INS_ARRAY, ADDRMETH_Y|OPTYPE_b|OP_W, OP_REG|OP_R,              ARG_NONE,        cpu_80386, "insb",   0,                  2+REG_DWORD_OFFSET, 0}, /* 0x6C */
    { 0,  INS_MOVE|INS_SYSTEM|INS_ARRAY, ADDRMETH_Y|OPTYPE_v|OP_W, OP_REG|OP_R,              ARG_NONE,        cpu_80386, "insd",   0,                  2+REG_DWORD_OFFSET, 0}, /* 0x6D */
    { 0,  INS_MOVE|INS_SYSTEM|INS_ARRAY, OP_REG|OP_W,              ADDRMETH_X|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "outsb",  2+REG_DWORD_OFFSET, 0,                  0}, /* 0x6E */
    { 0,  INS_MOVE|INS_SYSTEM|INS_ARRAY, OP_REG|OP_W,              ADDRMETH_X|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "outsb",  2+REG_DWORD_OFFSET, 0,                  0}, /* 0x6F */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jo",     0,                  0,                  0}, /* 0x70 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jno",    0,                  0,                  0}, /* 0x71 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jc",     0,                  0,                  0}, /* 0x72 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jnc",    0,                  0,                  0}, /* 0x73 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jz",     0,                  0,                  0}, /* 0x74 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jnz",    0,                  0,                  0}, /* 0x75 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jbe",    0,                  0,                  0}, /* 0x76 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "ja",     0,                  0,                  0}, /* 0x77 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "js",     0,                  0,                  0}, /* 0x78 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jns",    0,                  0,                  0}, /* 0x79 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jpe",    0,                  0,                  0}, /* 0x7A */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jpo",    0,                  0,                  0}, /* 0x7B */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jl",     0,                  0,                  0}, /* 0x7C */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jge",    0,                  0,                  0}, /* 0x7D */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jle",    0,                  0,                  0}, /* 0x7E */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jg",     0,                  0,                  0}, /* 0x7F */
    { 2,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x80 */
    { 3,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x81 */
    { 4,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x82 */
    { 5,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0x83 */
    { 0,  INS_FLAG,                      ADDRMETH_E|OPTYPE_b|OP_R, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "test",   0,                  0,                  0}, /* 0x84 */
    { 0,  INS_FLAG,                      ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "test",   0,                  0,                  0}, /* 0x85 */
    { 0,  INS_MOVE,                      ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_G|OPTYPE_b|OP_W, ARG_NONE,        cpu_80386, "xchg",   0,                  0,                  0}, /* 0x86 */
    { 0,  INS_MOVE,                      ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_W, ARG_NONE,        cpu_80386, "xchg",   0,                  0,                  0}, /* 0x87 */
    { 0,  INS_MOVE,                      ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0x88 */ // OPBYTE_b
    { 0,  INS_MOVE,                      ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_G|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0x89 */
    { 0,  INS_MOVE,                      ADDRMETH_G|OPTYPE_b|OP_W, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0x8A */
    { 0,  INS_MOVE,                      ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0x8B */
    { 0,  INS_MOVE,                      ADDRMETH_E|OPTYPE_w|OP_W, ADDRMETH_S|OPTYPE_w|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0x8C */
    { 0,  INS_PTR|INS_ARITH,             ADDRMETH_G|OPTYPE_v|OP_W, OPTYPE_d|ADDRMETH_M|OP_R, ARG_NONE,        cpu_80386, "lea",    0,                  0,                  0}, /* 0x8D */ // lcamtuf
    { 0,  INS_MOVE,                      ADDRMETH_S|OPTYPE_w|OP_W, ADDRMETH_E|OPTYPE_w|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0x8E */
    { 0,  INS_STACK,                     ADDRMETH_E|OPTYPE_v|OP_W, ARG_NONE,                 ARG_NONE,        cpu_80386, "pop",    0,                  0,                  0}, /* 0x8F */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "nop",    0,                  0,                  0}, /* 0x90 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              OP_REG|OP_W,              ARG_NONE,        cpu_80386, "xchg",   0+REG_DWORD_OFFSET, 1+REG_DWORD_OFFSET, 0}, /* 0x91 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              OP_REG|OP_W,              ARG_NONE,        cpu_80386, "xchg",   0+REG_DWORD_OFFSET, 2+REG_DWORD_OFFSET, 0}, /* 0x92 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              OP_REG|OP_W,              ARG_NONE,        cpu_80386, "xchg",   0+REG_DWORD_OFFSET, 3+REG_DWORD_OFFSET, 0}, /* 0x93 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              OP_REG|OP_W,              ARG_NONE,        cpu_80386, "xchg",   0+REG_DWORD_OFFSET, 4+REG_DWORD_OFFSET, 0}, /* 0x94 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              OP_REG|OP_W,              ARG_NONE,        cpu_80386, "xchg",   0+REG_DWORD_OFFSET, 5+REG_DWORD_OFFSET, 0}, /* 0x95 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              OP_REG|OP_W,              ARG_NONE,        cpu_80386, "xchg",   0+REG_DWORD_OFFSET, 6+REG_DWORD_OFFSET, 0}, /* 0x96 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              OP_REG|OP_W,              ARG_NONE,        cpu_80386, "xchg",   0+REG_DWORD_OFFSET, 7+REG_DWORD_OFFSET, 0}, /* 0x97 */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "cwde",   0,                  0,                  0}, /* 0x98 */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "cdq",    0,                  0,                  0}, /* 0x99 */
    { 0,  INS_SUB,                       ADDRMETH_A|OPTYPE_p|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "callf",  0,                  0,                  0}, /* 0x9A */
    { 0,  INS_SYSTEM,                    ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "wait",   0,                  0,                  0}, /* 0x9B */
    { 0,  INS_STACK,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "pushfd", 0,                  0,                  0}, /* 0x9C */
    { 0,  INS_STACK|INS_FLAG,            ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "popfd",  0,                  0,                  0}, /* 0x9D */
    { 0,  INS_ARITH,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "sahf",   0,                  0,                  0}, /* 0x9E */
    { 0,  INS_FLAG,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "lahf",   0,                  0,                  0}, /* 0x9F */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_O|OPTYPE_d|OP_R, ARG_NONE,        cpu_80386, "mov",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0xA0 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_O|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0xA1 */
    { 0,  INS_MOVE,                      ADDRMETH_O|OPTYPE_d|OP_W, OP_REG|OP_R,              ARG_NONE,        cpu_80386, "mov",    0,                  0+REG_BYTE_OFFSET,  0}, /* 0xA2 */
    { 0,  INS_MOVE,                      ADDRMETH_O|OPTYPE_v|OP_W, OP_REG|OP_R,              ARG_NONE,        cpu_80386, "mov",    0,                  0+REG_DWORD_OFFSET, 0}, /* 0xA3 */
    { 0,  INS_MOVE,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "movsb",  0,                  0,                  0}, /* 0xA4 */
    { 0,  INS_MOVE,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "movsd",  0,                  0,                  0}, /* 0xA5 */
    { 0,  INS_FLAG|INS_ARRAY,            ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "cmpsb",  0,                  0,                  0}, /* 0xA6 */
    { 0,  INS_FLAG|INS_ARRAY,            ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "cmpsd",  0,                  0,                  0}, /* 0xA7 */
    { 0,  INS_FLAG,                      OP_REG|OP_R,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "test",   0+REG_BYTE_OFFSET,  0,                  0}, /* 0xA8 */
    { 0,  INS_FLAG,                      OP_REG|OP_R,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "test",   0+REG_DWORD_OFFSET, 0,                  0}, /* 0xA9 */
    { 0,  INS_ARRAY,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "stosb",  0,                  0,                  0}, /* 0xAA */
    { 0,  INS_ARRAY,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "stosd",  0,                  0,                  0}, /* 0xAB */
    { 0,  INS_ARRAY,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "lodsb",  0,                  0,                  0}, /* 0xAC */
    { 0,  INS_ARRAY,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "lodsd",  0,                  0,                  0}, /* 0xAD */
    { 0,  INS_FLAG|INS_ARRAY,            ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "scasb",  0,                  0,                  0}, /* 0xAE */
    { 0,  INS_FLAG|INS_ARRAY,            ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "scasd",  0,                  0,                  0}, /* 0xAF */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    0+REG_BYTE_OFFSET,  0,                  0}, /* 0xB0 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    1+REG_BYTE_OFFSET,  0,                  0}, /* 0xB1 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    2+REG_BYTE_OFFSET,  0,                  0}, /* 0xB2 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    3+REG_BYTE_OFFSET,  0,                  0}, /* 0xB3 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    4+REG_BYTE_OFFSET,  0,                  0}, /* 0xB4 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    5+REG_BYTE_OFFSET,  0,                  0}, /* 0xB5 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    6+REG_BYTE_OFFSET,  0,                  0}, /* 0xB6 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    7+REG_BYTE_OFFSET,  0,                  0}, /* 0xB7 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    0+REG_DWORD_OFFSET, 0,                  0}, /* 0xB8 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    1+REG_DWORD_OFFSET, 0,                  0}, /* 0xB9 */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    2+REG_DWORD_OFFSET, 0,                  0}, /* 0xBA */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    3+REG_DWORD_OFFSET, 0,                  0}, /* 0xBB */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    4+REG_DWORD_OFFSET, 0,                  0}, /* 0xBC */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    5+REG_DWORD_OFFSET, 0,                  0}, /* 0xBD */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    6+REG_DWORD_OFFSET, 0,                  0}, /* 0xBE */
    { 0,  INS_MOVE,                      OP_REG|OP_W,              ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    7+REG_DWORD_OFFSET, 0,                  0}, /* 0xBF */
    { 6,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xC0 */
    { 7,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xC1 */
    { 0,  INS_RET|INS_BRANCH,            ADDRMETH_I|OPTYPE_w|OP_R, ARG_NONE,                 ARG_NONE,        cpu_80386, "ret",    0,                  0,                  0}, /* 0xC2 */
    { 0,  INS_RET|INS_BRANCH,            ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "ret",    0,                  0,                  0}, /* 0xC3 */
    { 0,  INS_PTR,                       ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_M|OPTYPE_p|OP_R, ARG_NONE,        cpu_80386, "les",    0,                  0,                  0}, /* 0xC4 */
    { 0,  INS_PTR,                       ADDRMETH_G|OPTYPE_v|OP_W, ADDRMETH_M|OPTYPE_p|OP_R, ARG_NONE,        cpu_80386, "lds",    0,                  0,                  0}, /* 0xC5 */
    { 0,  INS_MOVE,                      ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0xC6 */ // OPTYPE_b
    { 0,  INS_MOVE,                      ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE,        cpu_80386, "mov",    0,                  0,                  0}, /* 0xC7 */ // lcamtuf  v v
    { 0,  INS_FRAME,                     ADDRMETH_I|OPTYPE_w|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "enter",  0,                  0,                  0}, /* 0xC8 */
    { 0,  INS_FRAME,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "leave",  0,                  0,                  0}, /* 0xC9 */
    { 0,  INS_RET|INS_BRANCH,            ADDRMETH_I|OPTYPE_w|OP_R, ARG_NONE,                 ARG_NONE,        cpu_80386, "retf",   0,                  0,                  0}, /* 0xCA */
    { 0,  INS_RET|INS_BRANCH,            ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "retf",   0,                  0,                  0}, /* 0xCB */
    { 0,  INS_SYSTEM,                    ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "int3",   0,                  0,                  0}, /* 0xCC */
    { 0,  INS_SYSTEM,                    ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,                 ARG_NONE,        cpu_80386, "int",    0,                  0,                  0}, /* 0xCD */
    { 0,  INS_SYSTEM,                    ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "into",   0,                  0,                  0}, /* 0xCE */
    { 0,  INS_BRANCH|INS_RET|INS_SYSTEM, ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "iret",   0,                  0,                  0}, /* 0xCF */
    { 8,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xD0 */
    { 9,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xD1 */
    { 10, 0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xD2 */
    { 11, 0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xD3 */
    { 0,  INS_ARITH,                     ADDRMETH_I|OPTYPE_b|OP_W, ARG_NONE,                 ARG_NONE,        cpu_80386, "aam",    0,                  0,                  0}, /* 0xD4 */
    { 0,  INS_ARITH,                     ADDRMETH_I|OPTYPE_b|OP_W, ARG_NONE,                 ARG_NONE,        cpu_80386, "aad",    0,                  0,                  0}, /* 0xD5 */
    { 0,  INS_FLAG,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "setalc", 0,                  0,                  0}, /* 0xD6 */
    { 0,  INS_ARRAY,                     ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "xlat",   0,                  0,                  0}, /* 0xD7 */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xD8 */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xD9 */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xDA */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xDB */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xDC */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xDD */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xDE */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xDF */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "loopnz", 0,                  0,                  0}, /* 0xE0 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "loopz",  0,                  0,                  0}, /* 0xE1 */
    { 0,  INS_BRANCH,                    ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "loop",   0,                  0,                  0}, /* 0xE2 */
    { 0,  INS_COND,                      ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jcxz",   0,                  0,                  0}, /* 0xE3 */
    { 0,  INS_MOVE|INS_SYSTEM,           OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "in",     0+REG_BYTE_OFFSET,  0,                  0}, /* 0xE4 */
    { 0,  INS_MOVE|INS_SYSTEM,           OP_REG|OP_W,              ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE,        cpu_80386, "in",     0+REG_DWORD_OFFSET, 0,                  0}, /* 0xE5 */
    { 0,  INS_MOVE|INS_SYSTEM,           ADDRMETH_I|OPTYPE_b|OP_W, OP_REG|OP_R,              ARG_NONE,        cpu_80386, "out",    0,                  0+REG_BYTE_OFFSET,  0}, /* 0xE6 */
    { 0,  INS_MOVE|INS_SYSTEM,           ADDRMETH_I|OPTYPE_b|OP_W, OP_REG|OP_R,              ARG_NONE,        cpu_80386, "out",    0,                  0+REG_DWORD_OFFSET, 0}, /* 0xE7 */
    { 0,  INS_SUB,                       ADDRMETH_J|OPTYPE_v|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "call",   0,                  0,                  0}, /* 0xE8 */
    { 0,  INS_BRANCH,                    ADDRMETH_J|OPTYPE_v|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jmp",    0,                  0,                  0}, /* 0xE9 */
    { 0,  INS_BRANCH,                    ADDRMETH_A|OPTYPE_p|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jmp",    0,                  0,                  0}, /* 0xEA */
    { 0,  INS_BRANCH,                    ADDRMETH_J|OPTYPE_b|OP_X, ARG_NONE,                 ARG_NONE,        cpu_80386, "jmp",    0,                  0,                  0}, /* 0xEB */
    { 0,  INS_MOVE|INS_SYSTEM,           OP_REG|OP_W,              OP_REG|OP_R,              ARG_NONE,        cpu_80386, "in",     0+REG_BYTE_OFFSET,  2+REG_WORD_OFFSET,  0}, /* 0xEC */
    { 0,  INS_MOVE|INS_SYSTEM,           OP_REG|OP_W,              OP_REG|OP_R,              ARG_NONE,        cpu_80386, "in",     0+REG_DWORD_OFFSET, 2+REG_WORD_OFFSET,  0}, /* 0xED */
    { 0,  INS_MOVE|INS_SYSTEM,           OP_REG|OP_W,              OP_REG|OP_R,              ARG_NONE,        cpu_80386, "out",    2+REG_WORD_OFFSET,  0+REG_BYTE_OFFSET,  0}, /* 0xEE */
    { 0,  INS_MOVE|INS_SYSTEM,           OP_REG|OP_W,              OP_REG|OP_R,              ARG_NONE,        cpu_80386, "out",    2+REG_WORD_OFFSET,  0+REG_DWORD_OFFSET, 0}, /* 0xEF */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "lock:",  0,                  0,                  0}, /* 0xF0 */
    { 0,  0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "smi",    0,                  0,                  0}, /* 0xF1 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "repne:", 0,                  0,                  0}, /* 0xF2 */
    { 0,  INSTR_PREFIX,                  ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "rep:",   0,                  0,                  0}, /* 0xF3 */
    { 0,  INS_SYSTEM,                    ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "hlt",    0,                  0,                  0}, /* 0xF4 */
    { 0,  INS_FLAG,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "cmc",    0,                  0,                  0}, /* 0xF5 */
    { 12, 0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xF6 */
    { 13, 0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xF7 */
    { 0,  INS_FLAG,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "clc",    0,                  0,                  0}, /* 0xF8 */
    { 0,  INS_FLAG,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "stc",    0,                  0,                  0}, /* 0xF9 */
    { 0,  INS_FLAG|INS_SYSTEM,           ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "cli",    0,                  0,                  0}, /* 0xFA */
    { 0,  INS_FLAG|INS_SYSTEM,           ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "sti",    0,                  0,                  0}, /* 0xFB */
    { 0,  INS_FLAG,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "cld",    0,                  0,                  0}, /* 0xFC */
    { 0,  INS_FLAG,                      ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, "std",    0,                  0,                  0}, /* 0xFD */
    { 14, 0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}, /* 0xFE */
    { 15, 0,                             ARG_NONE,                 ARG_NONE,                 ARG_NONE,        cpu_80386, {0},      0,                  0,                  0}  /* 0xFF */
};

instr tbl_0F[] = {
    { 16, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           {0},         0,                  0, 0},                 /* 0x0  */
    { 17, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           {0},         0,                  0, 0},                 /* 0x1  */
    { 0,  INS_SYSTEM,          ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_w|OP_R,  ARG_NONE,                 cpu_80386,           "lar",       0,                  0, 0},                 /* 0x2  */
    { 0,  INS_SYSTEM,          ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_w|OP_R,  ARG_NONE,                 cpu_80386,           "lsl",       0,                  0, 0},                 /* 0x3  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x4  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x5  */
    { 0,  INS_FLAG|INS_SYSTEM, ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "clts",      0,                  0, 0},                 /* 0x6  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x7  */
    { 0,  INS_SYSTEM,          ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80486,           "invd",      0,                  0, 0},                 /* 0x8  */
    { 0,  INS_SYSTEM,          ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80486,           "wbinvd",    0,                  0, 0},                 /* 0x9  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "cflsh",     0,                  0, 0},                 /* 0xA  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "ud2",       0,                  0, 0},                 /* 0xB  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xC  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xD  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xE  */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xF  */
    { 0,  INS_MOVE,            ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "movups",    0,                  0, 0},                 /* 0x10 */
    { 0,  INS_MOVE,            ADDRMETH_W|OPTYPE_ps|OP_W, ADDRMETH_V|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "movups",    0,                  0, 0},                 /* 0x11 */
    { 0,  INS_MOVE,            ADDRMETH_W|OPTYPE_q|OP_W,  ADDRMETH_V|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "movlps",    0,                  0, 0},                 /* 0x12 */
    { 0,  INS_MOVE,            ADDRMETH_V|OPTYPE_q|OP_W,  ADDRMETH_W|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "movlps",    0,                  0, 0},                 /* 0x13 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "unpcklps",  0,                  0, 0},                 /* 0x14 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "unpckhps",  0,                  0, 0},                 /* 0x15 */
    { 0,  INS_MOVE,            ADDRMETH_V|OPTYPE_q|OP_W,  ADDRMETH_W|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "movhps",    0,                  0, 0},                 /* 0x16 */
    { 0,  INS_MOVE,            ADDRMETH_W|OPTYPE_q|OP_W,  ADDRMETH_V|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "movhps",    0,                  0, 0},                 /* 0x17 */
    { 19, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           {0},         0,                  0, 0},                 /* 0x18 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x19 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x1A */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x1B */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x1C */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x1D */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x1E */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x1F */
    { 0,  INS_MOVE,            ADDRMETH_R|OPTYPE_d|OP_W,  ADDRMETH_C|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "mov",       0,                  0, 0},                 /* 0x20 */
    { 0,  INS_MOVE,            ADDRMETH_R|OPTYPE_d|OP_W,  ADDRMETH_D|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "mov",       0,                  0, 0},                 /* 0x21 */
    { 0,  INS_MOVE,            ADDRMETH_C|OPTYPE_d|OP_W,  ADDRMETH_R|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "mov",       0,                  0, 0},                 /* 0x22 */
    { 0,  INS_MOVE,            ADDRMETH_D|OPTYPE_d|OP_W,  ADDRMETH_R|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "mov",       0,                  0, 0},                 /* 0x23 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x24 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x25 */
    { 0,  INS_MOVE,            ADDRMETH_I|OP_W,           ADDRMETH_I|OP_R,           ARG_NONE,                 cpu_80386|cpu_80486, "mov",       0,                  0, 0},                 /* 0x26 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x27 */
    { 0,  INS_MOVE,            ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "movaps",    0,                  0, 0},                 /* 0x28 */
    { 0,  INS_MOVE,            ADDRMETH_W|OPTYPE_ps|OP_W, ADDRMETH_V|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "movaps",    0,                  0, 0},                 /* 0x29 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_R, ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "cvtpi2ps",  0,                  0, 0},                 /* 0x2A */
    { 0,  INS_MOVE,            ADDRMETH_W|OPTYPE_ps|OP_W, ADDRMETH_V|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "movntps",   0,                  0, 0},                 /* 0x2B */
    { 0,  0,                   ADDRMETH_Q|OPTYPE_q|OP_R,  ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "cvttps2pi", 0,                  0, 0},                 /* 0x2C */
    { 0,  0,                   ADDRMETH_Q|OPTYPE_q|OP_R,  ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "cvtps2pi",  0,                  0, 0},                 /* 0x2D */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ss|OP_W, ADDRMETH_W|OPTYPE_ss|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "ucomiss",   0,                  0, 0},                 /* 0x2E */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ss|OP_W, ARG_NONE,                 cpu_PENTIUM2,        "comiss",    0,                  0, 0},                 /* 0x2F */
    { 0,  INS_SYSTEM,          ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTIUM,         "wrmsr",     0,                  0, 0},                 /* 0x30 */
    { 0,  INS_SYSTEM,          ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTIUM,         "rdtsc",     0,                  0, 0},                 /* 0x31 */
    { 0,  INS_SYSTEM,          ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTIUM,         "rdmsr",     0,                  0, 0},                 /* 0x32 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTPRO,         "rdpmc",     0,                  0, 0},                 /* 0x33 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTIUM2,        "sysenter",  0,                  0, 0},                 /* 0x34 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTIUM2,        "sysexit",   0,                  0, 0},                 /* 0x35 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x36 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x37 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x38 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x39 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x3A */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x3B */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x3C */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x3D */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x3E */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x3F */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovo",     0,                  0, 0},                 /* 0x40 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovno",    0,                  0, 0},                 /* 0x41 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovc",     0,                  0, 0},                 /* 0x42 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovnc",    0,                  0, 0},                 /* 0x43 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovz",     0,                  0, 0},                 /* 0x44 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovnz",    0,                  0, 0},                 /* 0x45 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovbe",    0,                  0, 0},                 /* 0x46 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmova",     0,                  0, 0},                 /* 0x47 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovs",     0,                  0, 0},                 /* 0x48 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovns",    0,                  0, 0},                 /* 0x49 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovpe",    0,                  0, 0},                 /* 0x4A */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovpo",    0,                  0, 0},                 /* 0x4B */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovl",     0,                  0, 0},                 /* 0x4C */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovge",    0,                  0, 0},                 /* 0x4D */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovle",    0,                  0, 0},                 /* 0x4E */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_PENTPRO,         "cmovg",     0,                  0, 0},                 /* 0x4F */
    { 0,  INS_MOVE,            ADDRMETH_E|OPTYPE_d|OP_W,  ADDRMETH_V|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "movmskps",  0,                  0, 0},                 /* 0x50 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "sqrtps",    0,                  0, 0},                 /* 0x51 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "rsqrtps",   0,                  0, 0},                 /* 0x52 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "rcpps",     0,                  0, 0},                 /* 0x53 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "andps",     0,                  0, 0},                 /* 0x54 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "andnps",    0,                  0, 0},                 /* 0x55 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "orps",      0,                  0, 0},                 /* 0x56 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "xorps",     0,                  0, 0},                 /* 0x57 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "addps",     0,                  0, 0},                 /* 0x58 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_R, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "mulps",     0,                  0, 0},                 /* 0x59 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x5A */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x5B */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "subps",     0,                  0, 0},                 /* 0x5C */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "minps",     0,                  0, 0},                 /* 0x5D */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "divps",     0,                  0, 0},                 /* 0x5E */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "maxps",     0,                  0, 0},                 /* 0x5F */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "punpcklbw", 0,                  0, 0},                 /* 0x60 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "punpcklwd", 0,                  0, 0},                 /* 0x61 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "punpckldq", 0,                  0, 0},                 /* 0x62 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "packsswb",  0,                  0, 0},                 /* 0x63 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pcmpgtb",   0,                  0, 0},                 /* 0x64 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pcmpgtw",   0,                  0, 0},                 /* 0x65 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pcmpgtd",   0,                  0, 0},                 /* 0x66 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "packuswb",  0,                  0, 0},                 /* 0x67 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "punpckhbw", 0,                  0, 0},                 /* 0x68 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "punpckhwd", 0,                  0, 0},                 /* 0x69 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "punpckhdq", 0,                  0, 0},                 /* 0x6A */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "packssdw",  0,                  0, 0},                 /* 0x6B */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x6C */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x6D */
    { 0,  INS_MOVE,            ADDRMETH_P|OPTYPE_d|OP_W,  ADDRMETH_E|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "movd",      0,                  0, 0},                 /* 0x6E */
    { 0,  INS_MOVE,            ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "movq",      0,                  0, 0},                 /* 0x6F */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ADDRMETH_I|OPTYPE_b|OP_R, cpu_PENTIUM2,        "pshuf",     0,                  0, 0},                 /* 0x70 */
    { 19, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTMMX,         {0},         0,                  0, 0},                 /* 0x71 */
    { 20, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTMMX,         {0},         0,                  0, 0},                 /* 0x72 */
    { 21, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTMMX,         {0},         0,                  0, 0},                 /* 0x73 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pcmpeqb",   0,                  0, 0},                 /* 0x74 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pcmpeqw",   0,                  0, 0},                 /* 0x75 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pcmpeqd",   0,                  0, 0},                 /* 0x76 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTMMX,         "emms",      0,                  0, 0},                 /* 0x77 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x78 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x79 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x7A */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x7B */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x7C */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0x7D */
    { 0,  INS_MOVE,            ADDRMETH_E|OPTYPE_d|OP_W,  ADDRMETH_P|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "movd",      0,                  0, 0},                 /* 0x7E */
    { 0,  INS_MOVE,            ADDRMETH_Q|OPTYPE_q|OP_W,  ADDRMETH_P|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "movq",      0,                  0, 0},                 /* 0x7F */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jo",        0,                  0, 0},                 /* 0x80 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jno",       0,                  0, 0},                 /* 0x81 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jc",        0,                  0, 0},                 /* 0x82 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jnc",       0,                  0, 0},                 /* 0x83 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jz",        0,                  0, 0},                 /* 0x84 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jnz",       0,                  0, 0},                 /* 0x85 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jbe",       0,                  0, 0},                 /* 0x86 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "ja",        0,                  0, 0},                 /* 0x87 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "js",        0,                  0, 0},                 /* 0x88 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jns",       0,                  0, 0},                 /* 0x89 */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jpe",       0,                  0, 0},                 /* 0x8A */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jpo",       0,                  0, 0},                 /* 0x8B */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jl",        0,                  0, 0},                 /* 0x8C */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jge",       0,                  0, 0},                 /* 0x8D */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jle",       0,                  0, 0},                 /* 0x8E */
    { 0,  INS_COND,            ADDRMETH_J|OPTYPE_v|OP_X,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "jg",        0,                  0, 0},                 /* 0x8F */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "seto",      0,                  0, 0},                 /* 0x90 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setno",     0,                  0, 0},                 /* 0x91 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setc",      0,                  0, 0},                 /* 0x92 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setnc",     0,                  0, 0},                 /* 0x93 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setz",      0,                  0, 0},                 /* 0x94 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setnz",     0,                  0, 0},                 /* 0x95 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setbe",     0,                  0, 0},                 /* 0x96 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "seta",      0,                  0, 0},                 /* 0x97 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "sets",      0,                  0, 0},                 /* 0x98 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setns",     0,                  0, 0},                 /* 0x99 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setpe",     0,                  0, 0},                 /* 0x9A */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setpo",     0,                  0, 0},                 /* 0x9B */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setl",      0,                  0, 0},                 /* 0x9C */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setge",     0,                  0, 0},                 /* 0x9D */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setle",     0,                  0, 0},                 /* 0x9E */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_b|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "setg",      0,                  0, 0},                 /* 0x9F */
    { 0,  INS_STACK,           OP_REG|OP_R,               ARG_NONE,                  ARG_NONE,                 cpu_80386,           "push",      4+REG_SEG_OFFSET,   0, 0},                 /* 0xA0 */
    { 0,  INS_STACK,           OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80386,           "pop",       4+REG_SEG_OFFSET,   0, 0},                 /* 0xA1 */
    { 0,  INS_SYSTEM,          ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80486,           "cpuid",     0,                  0, 0},                 /* 0xA2 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_v|OP_R,  ADDRMETH_G|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_80386,           "bt",        0,                  0, 0},                 /* 0xA3 */
    { 0,  INS_ARITH,           ADDRMETH_E|OPTYPE_v|OP_W,  ADDRMETH_G|OPTYPE_v|OP_R,  ADDRMETH_I|OPTYPE_b|OP_R, cpu_80386,           "shld",      0,                  0, 0},                 /* 0xA4 */
    { 0,  INS_ARITH,           ADDRMETH_E|OPTYPE_v|OP_W,  ADDRMETH_G|OPTYPE_v|OP_R,  ADDRMETH_I|OP_R|OP_REG,   cpu_80386,           "shld",      0,                  0, 1+REG_BYTE_OFFSET}, /* 0xA5 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xA6 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xA7 */
    { 0,  INS_STACK,           OP_REG|OP_R,               ARG_NONE,                  ARG_NONE,                 cpu_80386,           "push",      5+REG_SEG_OFFSET,   0, 0},                 /* 0xA8 */
    { 0,  INS_STACK,           OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80386,           "pop",       5+REG_SEG_OFFSET,   0, 0},                 /* 0xA9 */
    { 0,  INS_SYSTEM,          ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "rsm",       0,                  0, 0},                 /* 0xAA */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_v|OP_R,  ADDRMETH_G|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_80386,           "bts",       0,                  0, 0},                 /* 0xAB */
    { 0,  INS_ARITH,           ADDRMETH_E|OPTYPE_v|OP_W,  ADDRMETH_G|OPTYPE_v|OP_R,  ADDRMETH_I|OPTYPE_b|OP_R, cpu_80386,           "shrd",      0,                  0, 0},                 /* 0xAC */
    { 0,  INS_ARITH,           ADDRMETH_E|OPTYPE_v|OP_W,  ADDRMETH_G|OPTYPE_v|OP_R,  ADDRMETH_I|OP_R|OP_REG,   cpu_80386,           "shrd",      0,                  0, 1+REG_BYTE_OFFSET}, /* 0xAD */
    { 22, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTIUM2,        {0},         0,                  0, 0},                 /* 0xAE */
    { 0,  INS_ARITH,           ADDRMETH_G|OPTYPE_v|OP_R,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_80386,           "imul",      0,                  0, 0},                 /* 0xAF */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_E|OPTYPE_b|OP_W,  ADDRMETH_G|OPTYPE_b|OP_W,  ARG_NONE,                 cpu_80486,           "cmpxchg",   0,                  0, 0},                 /* 0xB0 */
    { 0,  INS_FLAG|INS_MOVE,   ADDRMETH_E|OPTYPE_v|OP_W,  ADDRMETH_G|OPTYPE_v|OP_W,  ARG_NONE,                 cpu_80486,           "cmpxchg",   0,                  0, 0},                 /* 0xB1 */
    { 0,  INS_PTR,             ADDRMETH_M|OPTYPE_p|OP_W,  ADDRMETH_I|OP_R,           ARG_NONE,                 cpu_80386,           "lss",       0,                  0, 0},                 /* 0xB2 */
    { 0,  INS_FLAG,            ADDRMETH_E|OPTYPE_v|OP_R,  ADDRMETH_G|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_80386,           "btr",       0,                  0, 0},                 /* 0xB3 */
    { 0,  INS_PTR,             ADDRMETH_M|OPTYPE_p|OP_W,  ADDRMETH_I|OP_R,           ARG_NONE,                 cpu_80386,           "lfs",       0,                  0, 0},                 /* 0xB4 */
    { 0,  INS_PTR,             ADDRMETH_M|OPTYPE_p|OP_W,  ADDRMETH_I|OP_R,           ARG_NONE,                 cpu_80386,           "lgs",       0,                  0, 0},                 /* 0xB5 */
    { 0,  INS_MOVE,            ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "movzx",     0,                  0, 0},                 /* 0xB6 */ // lcamtufized
    { 0,  INS_MOVE,            ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "movzx",     0,                  0, 0},                 /* 0xB7 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xB8 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           "ud1",       0,                  0, 0},                 /* 0xB9 */
    { 23, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_80386,           {0},         0,                  0, 0},                 /* 0xBA */
    { 0,  INS_FLAG|INS_LOGIC,  ADDRMETH_E|OPTYPE_v|OP_R,  ADDRMETH_G|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_80386,           "btc",       0,                  0, 0},                 /* 0xBB */
    { 0,  INS_FLAG,            ADDRMETH_G|OPTYPE_v|OP_R,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_80386,           "bsf",       0,                  0, 0},                 /* 0xBC */
    { 0,  INS_FLAG,            ADDRMETH_G|OPTYPE_v|OP_R,  ADDRMETH_E|OPTYPE_v|OP_R,  ARG_NONE,                 cpu_80386,           "bsr",       0,                  0, 0},                 /* 0xBD */
    { 0,  INS_MOVE,            ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "movsx",     0,                  0, 0},                 /* 0xBE */
    { 0,  INS_MOVE,            ADDRMETH_G|OPTYPE_v|OP_W,  ADDRMETH_E|OPTYPE_d|OP_R,  ARG_NONE,                 cpu_80386,           "movsx",     0,                  0, 0},                 /* 0xBF */
    { 0,  INS_ARITH,           ADDRMETH_E|OPTYPE_b|OP_W,  ADDRMETH_G|OPTYPE_b|OP_W,  ARG_NONE,                 cpu_80486,           "xadd",      0,                  0, 0},                 /* 0xC0 */
    { 0,  INS_ARITH,           ADDRMETH_E|OPTYPE_v|OP_W,  ARG_NONE,                  ARG_NONE,                 cpu_80486,           "xadd",      0,                  0, 0},                 /* 0xC1 */
    { 24, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTIUM2,        {0},         0,                  0, 0},                 /* 0xC2 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xC3 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_E|OPTYPE_d|OP_R,  ADDRMETH_I|OPTYPE_b|OP_R, cpu_PENTIUM2,        "pinsrw",    0,                  0, 0},                 /* 0xC4 */
    { 0,  0,                   ADDRMETH_G|OPTYPE_d|OP_W,  ADDRMETH_P|OPTYPE_q|OP_R,  ADDRMETH_I|OPTYPE_b|OP_R, cpu_PENTIUM2,        "pextrw",    0,                  0, 0},                 /* 0xC5 */
    { 0,  0,                   ADDRMETH_V|OPTYPE_ps|OP_W, ADDRMETH_W|OPTYPE_ps|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, cpu_PENTIUM2,        "shufps",    0,                  0, 0},                 /* 0xC6 */
    { 25, 0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 cpu_PENTMMX,         {0},         0,                  0, 0},                 /* 0xC7 */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     0+REG_DWORD_OFFSET, 0, 0},                 /* 0xC8 */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     1+REG_DWORD_OFFSET, 0, 0},                 /* 0xC9 */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     2+REG_DWORD_OFFSET, 0, 0},                 /* 0xCA */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     3+REG_DWORD_OFFSET, 0, 0},                 /* 0xCB */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     4+REG_DWORD_OFFSET, 0, 0},                 /* 0xCC */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     5+REG_DWORD_OFFSET, 0, 0},                 /* 0xCD */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     6+REG_DWORD_OFFSET, 0, 0},                 /* 0xCE */
    { 0,  INS_MOVE,            OP_REG|OP_W,               ARG_NONE,                  ARG_NONE,                 cpu_80486,           "bswap",     7+REG_DWORD_OFFSET, 0, 0},                 /* 0xCF */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xD0 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psrlw",     0,                  0, 0},                 /* 0xD1 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psrld",     0,                  0, 0},                 /* 0xD2 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psrlq",     0,                  0, 0},                 /* 0xD3 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xD4 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pmullw",    0,                  0, 0},                 /* 0xD5 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xD6 */
    { 0,  0,                   ADDRMETH_G|OPTYPE_d|OP_W,  ADDRMETH_P|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pmovmskb",  0,                  0, 0},                 /* 0xD7 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psubusb",   0,                  0, 0},                 /* 0xD8 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psubusw",   0,                  0, 0},                 /* 0xD9 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pminub",    0,                  0, 0},                 /* 0xDA */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pand",      0,                  0, 0},                 /* 0xDB */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "paddusb",   0,                  0, 0},                 /* 0xDC */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "paddusw",   0,                  0, 0},                 /* 0xDD */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pmaxub",    0,                  0, 0},                 /* 0xDE */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pandn",     0,                  0, 0},                 /* 0xDF */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pavgb",     0,                  0, 0},                 /* 0xE0 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psraw",     0,                  0, 0},                 /* 0xE1 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psrad",     0,                  0, 0},                 /* 0xE2 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pavgw",     0,                  0, 0},                 /* 0xE3 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pmulhuw",   0,                  0, 0},                 /* 0xE4 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pmulhw",    0,                  0, 0},                 /* 0xE5 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xE6 */
    { 0,  INS_MOVE,            ADDRMETH_W|OPTYPE_q|OP_W,  ADDRMETH_V|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "movntq",    0,                  0, 0},                 /* 0xE7 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psubsb",    0,                  0, 0},                 /* 0xE8 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psubsw",    0,                  0, 0},                 /* 0xE9 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pminsw",    0,                  0, 0},                 /* 0xEA */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "por",       0,                  0, 0},                 /* 0xEB */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "paddsb",    0,                  0, 0},                 /* 0xEC */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "paddsw",    0,                  0, 0},                 /* 0xED */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "pmaxsw",    0,                  0, 0},                 /* 0xEE */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pxor",      0,                  0, 0},                 /* 0xEF */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xF0 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psllw",     0,                  0, 0},                 /* 0xF1 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pslld",     0,                  0, 0},                 /* 0xF2 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psllq",     0,                  0, 0},                 /* 0xF3 */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xF4 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "pmaddwd",   0,                  0, 0},                 /* 0xF5 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTIUM2,        "psadbw",    0,                  0, 0},                 /* 0xF6 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_pi|OP_W, ADDRMETH_Q|OPTYPE_pi|OP_R, ARG_NONE,                 cpu_PENTIUM2,        "maskmovq",  0,                  0, 0},                 /* 0xF7 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psubb",     0,                  0, 0},                 /* 0xF8 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psubw",     0,                  0, 0},                 /* 0xF9 */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "psubd",     0,                  0, 0},                 /* 0xFA */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0},                 /* 0xFB */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "paddb",     0,                  0, 0},                 /* 0xFC */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "paddw",     0,                  0, 0},                 /* 0xFD */
    { 0,  0,                   ADDRMETH_P|OPTYPE_q|OP_W,  ADDRMETH_Q|OPTYPE_q|OP_R,  ARG_NONE,                 cpu_PENTMMX,         "paddd",     0,                  0, 0},                 /* 0xFE */
    { 0,  0,                   ARG_NONE,                  ARG_NONE,                  ARG_NONE,                 0,                   {0},         0,                  0, 0}                  /* 0xFF */
};

instr tbl_0F00[] = {
    { 0, INS_SYSTEM, ADDRMETH_E|OPTYPE_w|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sldt", 0, 0, 0}, /* 0x0 */
    { 0, 0,          ADDRMETH_E|OPTYPE_w|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "str",  0, 0, 0}, /* 0x1 */
    { 0, INS_SYSTEM, ADDRMETH_E|OPTYPE_w|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lldt", 0, 0, 0}, /* 0x2 */
    { 0, INS_SYSTEM, ADDRMETH_E|OPTYPE_w|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "ltr",  0, 0, 0}, /* 0x3 */
    { 0, INS_SYSTEM, ADDRMETH_E|OPTYPE_w|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "verr", 0, 0, 0}, /* 0x4 */
    { 0, INS_SYSTEM, ADDRMETH_E|OPTYPE_w|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "verw", 0, 0, 0}, /* 0x5 */
    { 0, 0,          ARG_NONE,                 ARG_NONE, ARG_NONE, 0,         {0},    0, 0, 0}, /* 0x6 */
    { 0, 0,          ARG_NONE,                 ARG_NONE, ARG_NONE, 0,         {0},    0, 0, 0}  /* 0x7 */
};

instr tbl_0F01[] = {
    { 0, INS_SYSTEM, ADDRMETH_M|OPTYPE_s|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sgdt",   0, 0, 0}, /* 0x0 */
    { 0, INS_SYSTEM, ADDRMETH_M|OPTYPE_s|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sidt",   0, 0, 0}, /* 0x1 */
    { 0, INS_SYSTEM, ADDRMETH_M|OPTYPE_s|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lgdt",   0, 0, 0}, /* 0x2 */
    { 0, INS_SYSTEM, ADDRMETH_M|OPTYPE_s|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lidt",   0, 0, 0}, /* 0x3 */
    { 0, INS_SYSTEM, ADDRMETH_E|OPTYPE_w|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "smsw",   0, 0, 0}, /* 0x4 */
    { 0, 0,          ARG_NONE,                 ARG_NONE, ARG_NONE, 0,         {0},      0, 0, 0}, /* 0x5 */
    { 0, INS_SYSTEM, ADDRMETH_E|OPTYPE_w|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lmsw",   0, 0, 0}, /* 0x6 */
    { 0, INS_SYSTEM, ADDRMETH_M|OPTYPE_b|OP_R, ARG_NONE, ARG_NONE, cpu_80486, "invlpg", 0, 0, 0}  /* 0x7 */
};

instr tbl_0F18[] = {
    { 0, 0, OP_W,        ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 0,                 0, 0}, /* 0x0 */
    { 0, 0, OP_REG|OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 0+REG_TEST_OFFSET, 0, 0}, /* 0x1 */
    { 0, 0, OP_REG|OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 1+REG_TEST_OFFSET, 0, 0}, /* 0x2 */
    { 0, 0, OP_REG|OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 2+REG_TEST_OFFSET, 0, 0}, /* 0x3 */
    { 0, 0, ARG_NONE,    ARG_NONE, ARG_NONE, 0,            {0},        0,                 0, 0}, /* 0x4 */
    { 0, 0, ARG_NONE,    ARG_NONE, ARG_NONE, 0,            {0},        0,                 0, 0}, /* 0x5 */
    { 0, 0, ARG_NONE,    ARG_NONE, ARG_NONE, 0,            {0},        0,                 0, 0}, /* 0x6 */
    { 0, 0, ARG_NONE,    ARG_NONE, ARG_NONE, 0,            {0},        0,                 0, 0}  /* 0x7 */
};

instr tbl_0F71[] = {
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x0 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x1 */
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0}, /* 0x2 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x3 */
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0}, /* 0x4 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x5 */
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0}, /* 0x6 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}  /* 0x7 */
};

instr tbl_0F72[] = {
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x0 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x1 */
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0}, /* 0x2 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x3 */
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0}, /* 0x4 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}, /* 0x5 */
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0}, /* 0x6 */
    { 0, 0, ARG_NONE,                 ARG_NONE,                 ARG_NONE, 0,           {0},     0, 0, 0}  /* 0x7 */
};

instr tbl_0F73[] = {
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0}, /* 0x0 */
    { 0, 0, ADDRMETH_P|OPTYPE_q|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0}  /* 0x1 */
};

instr tbl_0FAE[] = {
    { 0, INS_FPU, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX,  "fxsave",  0, 0, 0}, /* 0x0 */
    { 0, INS_FPU, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX,  "fxrstor", 0, 0, 0}, /* 0x1 */
    { 0, 0,       ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "ldmxcsr", 0, 0, 0}, /* 0x2 */
    { 0, 0,       ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "stmxcsr", 0, 0, 0}, /* 0x3 */
    { 0, 0,       ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sfence",  0, 0, 0}  /* 0x4 */
};

instr tbl_0FBA[] = {
    { 0, INS_FLAG,           ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "bt",  0, 0, 0}, /* 0x0 */
    { 0, INS_FLAG,           ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0}, /* 0x1 */
    { 0, INS_FLAG,           ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0}, /* 0x2 */
    { 0, INS_FLAG|INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0}  /* 0x3 */
};

instr tbl_0FC7[] = {
    { 0, INS_FLAG|INS_MOVE, ADDRMETH_M|OPTYPE_q|OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM, "cmpxch8b", 0, 0, 0} /* 0x0 */
};

instr tbl_80[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0}, /* 0x0 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "or",  0, 0, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0}, /* 0x3 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0}, /* 0x5 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0}, /* 0x6 */
    { 0, INS_FLAG,  ADDRMETH_E|OPTYPE_b|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0}  /* 0x7 */
};

instr tbl_81[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0}, /* 0x0 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "or",  0, 0, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0}, /* 0x3 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0}, /* 0x5 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0}, /* 0x6 */
    { 0, INS_FLAG,  ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0}  /* 0x7 */
};

instr tbl_82[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0}, /* 0x0 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "or",  0, 0, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0}, /* 0x3 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0}, /* 0x5 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0}, /* 0x6 */
    { 0, INS_FLAG,  ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0}  /* 0x7 */
};

instr tbl_83[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0}, /* 0x0 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "or",  0, 0, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0}, /* 0x3 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0}, /* 0x5 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0}, /* 0x6 */
    { 0, INS_FLAG,  ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0}  /* 0x7 */
};

instr tbl_C0[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "rol", 0, 0, 0}, /* 0x0 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "ror", 0, 0, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "rcl", 0, 0, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "rcr", 0, 0, 0}, /* 0x3 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "shl", 0, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "shr", 0, 0, 0}, /* 0x5 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sal", 0, 0, 0}, /* 0x6 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sar", 0, 0, 0}  /* 0x7 */
};

instr tbl_C1[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "rol", 0, 0, 0}, /* 0x0 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "ror", 0, 0, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "rcl", 0, 0, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "rcr", 0, 0, 0}, /* 0x3 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "shl", 0, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "shr", 0, 0, 0}, /* 0x5 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sal", 0, 0, 0}, /* 0x6 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "sar", 0, 0, 0}  /* 0x7 */
};

instr tbl_D0[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "rol", 0, 1, 0}, /* 0x0 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "ror", 0, 1, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1, 0}, /* 0x3 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "shl", 0, 1, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "shr", 0, 1, 0}, /* 0x5 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "sal", 0, 1, 0}, /* 0x6 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "sar", 0, 1, 0}  /* 0x7 */
};

instr tbl_D1[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "rol", 0, 1, 0}, /* 0x0 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "ror", 0, 1, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1, 0}, /* 0x3 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "shl", 0, 1, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "shr", 0, 1, 0}, /* 0x5 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "sal", 0, 1, 0}, /* 0x6 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, ADDRMETH_I|OP_IMM|OP_R, ARG_NONE, cpu_80386, "sar", 0, 1, 0}  /* 0x7 */
};

instr tbl_D2[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "rol", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x0 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "ror", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x3 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "shl", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "shr", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x5 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "sal", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x6 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "sar", 0, 1+REG_BYTE_OFFSET, 0}  /* 0x7 */
};

instr tbl_D3[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "rol", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x0 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "ror", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x1 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x2 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x3 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "shl", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x4 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "shr", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x5 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "sal", 0, 1+REG_BYTE_OFFSET, 0}, /* 0x6 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_v|OP_W, OP_REG|OP_R, ARG_NONE, cpu_80386, "sar", 0, 1+REG_BYTE_OFFSET, 0}  /* 0x7 */
};

instr tbl_F6[] = {
    { 0, INS_FLAG,  ADDRMETH_I|OPTYPE_b|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "test", 0,                 0, 0}, /* 0x0 */
    { 0, INS_FLAG,  ADDRMETH_I|OPTYPE_b|OP_R, ADDRMETH_I|OPTYPE_b|OP_R, ARG_NONE, cpu_80386, "test", 0,                 0, 0}, /* 0x1 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_b|OP_W, ARG_NONE,                 ARG_NONE, cpu_80386, "not",  0,                 0, 0}, /* 0x2 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_b|OP_W, ARG_NONE,                 ARG_NONE, cpu_80386, "neg",  0,                 0, 0}, /* 0x3 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "mul",  0+REG_BYTE_OFFSET, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "imul", 0+REG_BYTE_OFFSET, 0, 0}, /* 0x5 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "div",  0+REG_BYTE_OFFSET, 0, 0}, /* 0x6 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "idiv", 0+REG_BYTE_OFFSET, 0, 0}  /* 0x7 */
};

instr tbl_F7[] = {
    { 0, INS_FLAG,  ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "test", 0,                  0, 0}, /* 0x0 */
    { 0, INS_FLAG,  ADDRMETH_E|OPTYPE_v|OP_R, ADDRMETH_I|OPTYPE_v|OP_R, ARG_NONE, cpu_80386, "test", 0,                  0, 0}, /* 0x1 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ARG_NONE,                 ARG_NONE, cpu_80386, "not",  0,                  0, 0}, /* 0x2 */
    { 0, INS_LOGIC, ADDRMETH_E|OPTYPE_v|OP_W, ARG_NONE,                 ARG_NONE, cpu_80386, "neg",  0,                  0, 0}, /* 0x3 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "mul",  0+REG_DWORD_OFFSET, 0, 0}, /* 0x4 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "imul", 0+REG_DWORD_OFFSET, 0, 0}, /* 0x5 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "div",  0+REG_DWORD_OFFSET, 0, 0}, /* 0x6 */
    { 0, INS_ARITH, OP_REG|OP_R,              ARG_NONE,                 ARG_NONE, cpu_80386, "idiv", 0+REG_DWORD_OFFSET, 0, 0}  /* 0x7 */
};

instr tbl_FE[] = {
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 0, 0, 0}, /* 0x0 */
    { 0, INS_ARITH, ADDRMETH_E|OPTYPE_b|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 0, 0, 0}  /* 0x1 */
};

instr tbl_FF[] = {
    { 0, INS_ARITH,  ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc",  0, 0, 0}, /* 0x0 */
    { 0, INS_ARITH,  ADDRMETH_E|OPTYPE_v|OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec",  0, 0, 0}, /* 0x1 */
    { 0, INS_SUB,    ADDRMETH_E|OPTYPE_v|OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0}, /* 0x2 */
    { 0, INS_SUB,    ADDRMETH_E|OPTYPE_p|OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0}, /* 0x3 */
    { 0, INS_BRANCH, ADDRMETH_E|OPTYPE_v|OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp",  0, 0, 0}, /* 0x4 */
    { 0, INS_BRANCH, ADDRMETH_E|OPTYPE_p|OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp",  0, 0, 0}, /* 0x5 */
    { 0, INS_STACK,  ADDRMETH_E|OPTYPE_v|OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0, 0, 0}, /* 0x6 */
    { 0, 0,          ARG_NONE,                 ARG_NONE, ARG_NONE, 0,         {0},    0, 0, 0}  /* 0x7 */
};

/* Init routine : used to set internal disassembler values */
inline void ext_arch_init( void *param) {
    settings = (struct EXT__ARCH *)param;

    if (! settings) return;

    /* Init register info */
    InitRegTable( );
    /* set CPU specific information */
    settings->reg_seg = REG_SEG_OFFSET;
    settings->reg_fp  = REG_FPU_OFFSET;
    settings->reg_in  =  0;
    settings->reg_out =  0;
    if ( settings->options & MODE_16_BIT ) {
        settings->sz_addr = 2;
        settings->sz_oper = 2;
        settings->SP = 4 + REG_WORD_OFFSET;
        settings->IP = REG_IP_INDEX;
        settings->reg_gen = REG_WORD_OFFSET;
    } else {
        settings->sz_addr = 4;
        settings->sz_oper = 4;
        settings->SP = 4 + REG_DWORD_OFFSET;
        settings->IP = REG_EIP_INDEX;
        settings->reg_gen = REG_DWORD_OFFSET;
    }
    settings->sz_inst = 0;
    settings->sz_byte = 8;
    settings->sz_word = 2;
    settings->sz_dword = 4;
    return;
}

/* Register Table Setup */
inline void InitRegTable( void ) {
    int x;

    settings->sz_regtable = 86;
    settings->reg_table = calloc( sizeof(struct REGTBL_ENTRY), 86);
    settings->reg_storage = calloc(12, 70);

    if (! settings->reg_table || ! settings->reg_storage) return;
    for (x = 0; x < 8; x++) {
        /* Add register : index into RegTable    Mnemonic        Size  */
        AddRegTableEntry( REG_DWORD_OFFSET + x, reg_dword[x],   REG_DWORD_SIZE);
        AddRegTableEntry( REG_WORD_OFFSET + x,  reg_word[x],    REG_WORD_SIZE);
        AddRegTableEntry( REG_BYTE_OFFSET + x,  reg_byte[x],    REG_BYTE_SIZE);
        AddRegTableEntry( REG_MMX_OFFSET + x,   reg_mmx[x],     REG_MMX_SIZE);
        AddRegTableEntry( REG_SIMD_OFFSET + x,  reg_simd[x],    REG_SIMD_SIZE);
        AddRegTableEntry( REG_DEBUG_OFFSET + x, reg_debug[x],   REG_DEBUG_SIZE);
        AddRegTableEntry( REG_CTRL_OFFSET + x,  reg_control[x], REG_CTRL_SIZE);
        AddRegTableEntry( REG_TEST_OFFSET + x,  reg_test[x],    REG_TEST_SIZE);
        AddRegTableEntry( REG_SEG_OFFSET + x,   reg_seg[x],     REG_SEG_SIZE);
        AddRegTableEntry( REG_FPU_OFFSET + x,   reg_fpu[x],     REG_FPU_SIZE);
    }
    /* add the irregular registers */
    AddRegTableEntry( REG_FLAGS_INDEX,    "eflags", REG_FLAGS_SIZE);
    AddRegTableEntry( REG_FPCTRL_INDEX,   "fpctrl", REG_FPCTRL_SIZE);
    AddRegTableEntry( REG_FPSTATUS_INDEX, "fpstat", REG_FPSTATUS_SIZE);
    AddRegTableEntry( REG_FPTAG_INDEX,    "fptag",  REG_FPTAG_SIZE);
    AddRegTableEntry( REG_EIP_INDEX,      "eip",    REG_EIP_SIZE);
    AddRegTableEntry( REG_IP_INDEX,       "ip",     REG_IP_SIZE);

    return;
}

inline void ext_arch_cleanup( void ) {
    if (settings->reg_table) free(settings->reg_table);
    if (settings->sz_regtable) settings->sz_regtable = 0;
    if (settings->reg_storage) free(settings->reg_storage);
    return;
}

/* --- Exported Information Routines -------------------------------------*/
/* These are used to pass information about the platform to the higher-level
 * disassembler  -- there will probably be more added when additional CPUs
 * are supported */
inline int get_prologue(struct code **table){
    /* This function and the following are kind of tricky. They fill 'table'
     * with an array of CODE structs; within the array, each 'prologue' is
     * represented by a series of CODE structs followed by a NULL code struct.
     * The number returned is the number of prologues. See the function
     * recognition pass for details on how to use these routines */
    struct code *t;
    int num = 2;
    // int i, j;

    t = (struct code *) calloc( sizeof( struct code ), 6);
    /* ------------------------------ customize this part only !! */
    /* prolog1:  push esp
     *           mov  ebp, esp
     *           sub  esp, ??? */
    strcpy( t[0].mnemonic, "push");
    t[0].dest = 5 + REG_DWORD_OFFSET;
    strcpy( t[1].mnemonic, "mov");
    t[1].dest = 5 + REG_DWORD_OFFSET;
    t[1].src= 4 + REG_DWORD_OFFSET;
    strcpy( t[2].mnemonic, "sub");
    t[2].dest = 4 + REG_DWORD_OFFSET;
    /* prolog2: enter */
    strcpy( t[4].mnemonic, "enter");
    /* ------------------------------- end customize-part */

    *table = t;
    return(num);
}

inline int get_epilogue(struct code **table){
    struct code *t;
    int num = 3;
    // int i, j;

    t = (struct code *) calloc( sizeof( struct code ), 6);
    /* ------------------------------ customize this part only !! */
    /* epilog1:  ret */
    strcpy( t[0].mnemonic, "ret");
    /* epilog2: retf */
    strcpy( t[2].mnemonic, "retf");
    /* epilog3: iret */
    strcpy( t[4].mnemonic, "iret");
    /* ------------------------------- end customize-part */

    *table = t;
    return(num);
}
/* get the effects on registers of a specified instruction */
inline int gen_reg_effect( char *mnemonic, struct code_effect *e){
    /* the mnemonic is used to determine the effects of instructions
     * which are predetermined, e.g. a call or a push affecting the
     * stack pointer. All effects dependent on operands are managed
     * by the calling program */

    /* Thus will have to be more complete... */
    if (! strncmp(mnemonic, "push", 4) ) {
        e->reg = settings->SP;
        e->change = -(settings->sz_addr);
        return(1);
    } else if (! strncmp(mnemonic, "pop", 3)) {
        e->reg = settings->SP;
        e->change = settings->sz_addr;
        return(1);
        //} else if (!strncmp(mnemonic, "call", 4)){
        //} else if (! strncmp(mnemonic, "ret", 3)) {
    }
    return(0);
}

/* generate intermediate code for a function */
inline int gen_int( int func_id __attribute__((unused))) {
    return(1);
}

/* ------------ Disassembly Routines ----------------------------------- */

inline int GetSizedOperand( int *op, const BYTE *buf, int size) {
    /* Copy 'size' bytes from *buf to *op
     * return number of bytes copied */
    /* TODO: call bastard functions for endian-independence */
    switch (size) {
        case 1:                 /* BYTE */
            *op = (signed char)buf[0];
            break;
        case 2:                 /* WORD */
            *op = *((signed short *)&buf[0]);
            break;
        case 6:
        case 8:                 /* QWORD */
            *op = *((signed long long*)&buf[0]);
            break;
        case 4:                 /* DWORD */
        default:
            *op = *((signed long *)&buf[0]);
            break;
    }
    return(size);
}

inline int DecodeByte(BYTE b, struct modRM_byte *modrm){
    /* generic bitfield-packing routine */

    modrm->mod = b >> 6;             /* top 2 bits */
    modrm->reg = ( b & 56 ) >> 3;    /* middle 3 bits */
    modrm->rm  = b & 7;              /* bottom 3 bits */

    return(0);
}

inline int DecodeSIB(const BYTE *b) {
    /* set Address Expression fields (scale, index, base, disp)
     * according to the contents of the SIB byte.
     *  b points to the SIB byte in the instruction-stream buffer; the
     *    byte after b[0] is therefore the byte after the SIB
     *  returns number of bytes 'used', including the SIB byte */
    int count = 1;      /* start at 1 for SIB byte */
    struct SIB_byte sib;

    DecodeByte(*b, (struct modRM_byte *) &sib); /* get bit-fields */

    if (sib.base == SIB_BASE_EBP && /* if base == 101 (ebp) */
            /* IF BASE == EBP, deal with exception */
            !(expr.disp) ) {             /*    if mod = 00 (no disp set) */
        /* IF (ModR/M did not create a Disp */
        /* ... create a 32-bit Displacement */
        expr.disp = AS_UINT(b[1]);
        /* Mark Addr Expression as having a DWORD for DISP */
        expr.flags |= ADDREXP_DWORD << ADDEXP_DISP_OFFSET;
        count += sizeof(DWORD);
    } else {
        /* ELSE BASE refers to a General Register */
        expr.base = sib.base;
        /* Mark Addr Expression as having a register for BASE */
        expr.flags |= ADDREXP_REG << ADDEXP_BASE_OFFSET;
    }
    if (sib.scale > 0){
        /* IF SCALE is not '1' */
        expr.scale = 0x01 << sib.scale; /* scale becomes 2, 4, 8 */
        /* Mark Addr Expression as having a BYTE for SCALE */
        expr.flags |= ADDREXP_BYTE << ADDEXP_SCALE_OFFSET;
    }
    if (sib.index != SIB_INDEX_NONE ){
        /* IF INDEX is not 'ESP' (100) */
        expr.index = sib.index;
        /* Mark Addr Expression as having a register for INDEX */
        expr.flags |= ADDREXP_REG << ADDEXP_INDEX_OFFSET;
    }

    return(count); /* return number of bytes processed */
}

/* TODO : Mark index modes
   Use addressing mode flags to imply arrays (index), structure (disp),
   two-dimensional arrays [disp + index], classes [ea reg], and so on.
   Don't forget to flag string (*SB, *SW) instructions
 */
/* returns number of bytes it decoded */
inline int DecodeModRM(const BYTE *b, int *op, int *op_flags, int reg_type,
        int size, int flags){
    /* create address expression and/or fill operand based on value of
     * ModR/M byte. Calls DecodeSIB as appropriate.
     *    b points to the loc of the modR/M byte in the instruction stream
     *    op points to the operand buffer
     *    op_flags points to the operand flags buffer
     *    reg_type encodes the type of register used in this instruction
     *    size specifies the default operand size for this instruction
     *    flags specifies whether the Reg or the mod+R/M fields are being decoded
     *  returns the number of bytes in the instruction, including modR/M */
    int count=1;    /* # of bytes decoded -- start with 1 for the modR/M byte */
    // int disp = 0;
    struct modRM_byte modrm;

    DecodeByte(*b, &modrm);       /* get bitfields */

    if (flags == MODRM_EA) {
        /* IF this is the mod + R/M operand */
        if ( modrm.mod ==  MODRM_MOD_NOEA ) { /* if mod == 11 */
            /* IF MOD == Register Only, no Address Expression */
            *op = modrm.rm + reg_type; /* operand to register ID */
            *op_flags &= 0xFFFF0FFF;
            *op_flags |= OP_REG;       /* flag operand as Register */
        } else if (modrm.mod == MODRM_MOD_NODISP) { /* if mod == 00 */
            /* IF MOD == No displacement, just Indirect Register */
            if (modrm.rm == MODRM_RM_NOREG) { /* if r/m == 101 */
                /* IF RM == No Register, just Displacement */
                /* This is an Intel Moronic Exception TM */
                if (size == sizeof(DWORD)) {
                    /* If Operand size is 32-bit */
                    expr.disp = AS_UINT(b[1]); /* save 32-bit displacement */
                    /* flag Addr Expression as having DWORD for DISP */
                    expr.flags |= ADDREXP_DWORD << ADDEXP_DISP_OFFSET;
                } else {
                    /* ELSE operand size is 16 bit */
                    expr.disp = (signed short)AS_USHORT(b[1]); /* save 16-bit displacement */
                    /* flag Addr Expression as having WORD for DISP */
                    expr.flags |= ADDREXP_WORD << ADDEXP_DISP_OFFSET;
                }
                count += size; /* add sizeof displacement to count */
            } else if (modrm.rm == MODRM_RM_SIB) { /* if r/m == 100 */
                /* ELSE IF an SIB byte is present */
                count += DecodeSIB(&b[1]);   /* add sizeof SIB to count */
            } else { /* modR/M specifies base register */
                /* ELSE RM encodes a general register */
                expr.base = modrm.rm;
                /* Flag AddrExpression as having a REGISTER for BASE */
                expr.flags |= ADDREXP_REG << ADDEXP_BASE_OFFSET;
            }
            *op_flags &= 0xFFFF0FFF;
            *op_flags |= OP_EXPR; /* flag operand as Address Expression */
        } else {
            /* ELSE mod + r/m specify a disp##[base] or disp##(SIB) */
            if ( modrm.mod == MODRM_MOD_DISP8 ) {
                /* If this is an 8-bit displacement */
                expr.disp = (signed char) b[1]; // LCAMTUF
                /* Flag AddrExpression as having a BYTE for DISP */
                expr.flags |= ADDREXP_BYTE << ADDEXP_DISP_OFFSET;
                count += sizeof(BYTE);  /* add sizeof displacement to count */
            } else {
                /* Displacement is dependent on operand size */
                if (size == sizeof(WORD)) {
                    expr.disp = (signed short)AS_USHORT(b[1]);
                    /* Flag AddrExpression as having a WORD for DISP */
                    expr.flags |= ADDREXP_WORD << ADDEXP_DISP_OFFSET;
                } else {
                    expr.disp = AS_UINT(b[1]);
                    /* Flag AddrExpression as having a DWORD for DISP */
                    expr.flags |= ADDREXP_DWORD << ADDEXP_DISP_OFFSET;
                }
                count += size;  /* add sizeof displacement to count */
            }
            if (modrm.rm == MODRM_RM_SIB) { /* rm == 100 */
                /* IF base is an AddrExpr specified by an SIB byte */
                count += DecodeSIB(&b[1]);
            } else {
                /* ELSE base is a general register */
                expr.base = modrm.rm; /* always a general_dword reg */
                /* Flag AddrExpression as having a REGISTER for BASE */
                expr.flags |= ADDREXP_REG << ADDEXP_BASE_OFFSET;
            }
            *op_flags &= 0xFFFF0FFF;
            *op_flags |= OP_EXPR; /* flag operand as Address Expression */
        }
        //if ( *op_flags &  OP_EXPR ) {
        if ( expr.flags ) {
            /* IF an address expression was created for this instruction */
            /* Set Operand to the ID of the AddrExpr */
            *op =
                DefineAddrExp(expr.scale,expr.index,expr.base,expr.disp,expr.flags);
        }
    } else {
        /* ELSE this is the 'reg' field : assign a register */
        /* set operand to register ID */
        *op = modrm.reg + reg_type;
        *op_flags |= OP_REG;
        count = 0;
    }

    return(count);       /* number of bytes found in instruction */
}

inline void apply_seg(unsigned int prefix, int *dest_flg){
    unsigned int seg = prefix & 0xF0000000;

    if ( seg == PREFIX_CS) *dest_flg |= OP_CODESEG;
    if ( seg == PREFIX_SS) *dest_flg |= OP_STACKSEG;
    if ( seg == PREFIX_DS) *dest_flg |= OP_DATASEG;
    if ( seg == PREFIX_ES) *dest_flg |= OP_EXTRASEG;
    if ( seg == PREFIX_FS) *dest_flg |= OP_DATA1SEG;
    if ( seg == PREFIX_GS) *dest_flg |= OP_DATA2SEG;

    return;
}

inline int InstDecode( instr *t, const BYTE *buf, struct code *c, DWORD rva __attribute__((unused))){

    /* Decode the operands of an instruction; calls DecodeModRM as
        * necessary, gets displacemnets and immeidate values, and sets the
        * values of operand and operand flag fields in the code struct.
        *    buf points to the byte *after* the opcode of the current instruction
        *        in the instruction stream
        *    t points to the representation of the instruction in the opcode
        *        table
        *    c points to the destination code structure which we are in the
        *        process of filling
        *    rva is the virtual address of the start of the current instruction;
        *        it may or may not prove useful.
        *    returns number of bytes found in addition to the actual opcode
        *    bytes.
        * note bytes defaults to 0, since disasm_addr takes care of the
        * opcode size ... everything else is dependent on operand
        * types.
        */
    /* bytes: size of curr instr; size: operand size */
    int x, bytes=0, size=0, op_size_flag = 0;
    int addr_size, op_size, op_notes; /* for override prefixes */
    unsigned int addr_meth, op_type, prefix;
    int genRegs;
    /* tables used to address each operands with the for loop */
    int operands[3] = {    t->dest,       t->src,       t->aux      };
    int op_flags[3] = {    t->destFlg,    t->srcFlg,    t->auxFlg   };
    /* destination buffers in the CODE struct */
    int *dest_buf[3] = {   &c->dest,      &c->src,      &c->aux     };
    int *dest_flg[3] = {   &c->destType,  &c->srcType,  &c->auxType };

    /* clear global ADDRESS EXPRESSION struct */
    memset( &expr, 0, sizeof( struct addr_exp));

    /*  ++++   1. Copy mnemonic and mnemonic-flags to CODE struct */
    if ( t->mnemonic)
        /* IF the instruction has a mnemonic, cat it to the mnemonic field */
        strcpy( c->mnemonic, t->mnemonic);
    c->mnemType |= t->mnemFlg; /* save INS_TYPE f;ags */

    /*  ++++   2. Handle opcode prefixes */
    prefix = c->mnemType & 0xFFF00000; /* store prefix flag in temp variable */
    c->mnemType &= 0x000FFFFF; /* clear prefix flags */
    addr_size = settings->sz_addr; /* set Address Size to Default Addr Size */
    if ( prefix & PREFIX_ADDR_SIZE) {
        /* IF Address Size Override Prefix is set */
        if ( addr_size == 4 ) addr_size = 2; /* that's right, it's a toggle */
        else addr_size = 4;
    }

    op_size = settings->sz_oper; /* Set Operand Size to Default Operand Size */
    if ( prefix & PREFIX_OP_SIZE) {
        /* IF Operand Size Override Prefix is set */
        if ( op_size == 4 ) op_size = 2; /* this one too */
        else op_size = 4;
    }

    /* these prepend the relevant string to the mnem */
    if ( prefix & PREFIX_LOCK)   c->mnemType |= INS_LOCK;
    if ( prefix & PREFIX_REPNZ)  c->mnemType |= INS_REPNZ;
    if ( prefix & PREFIX_REP || prefix & PREFIX_REPZ) c->mnemType |= INS_REPZ;
    /* this is ignored :P */
    // if ( prefix & PREFIX_SIMD) {}

    /*  ++++   3. Fill operands and operand-flags in CODE struct */
    for (x=0; x < 3; x++ ) {
        /* FOREACH Operand in (dest, src, aux) */
        /* set default register set to 16- or 32-bit regs */
        if ( op_size == 2)  genRegs = REG_WORD_OFFSET;
        else                genRegs = REG_DWORD_OFFSET;

        /* ++ Yank optype and addr mode out of operand flags */
        addr_meth = op_flags[x] & ADDRMETH_MASK;
        op_type   = op_flags[x] & OPTYPE_MASK;
        op_notes  = op_flags[x] & OPFLAGS_MASK; /* these are passed to bastard */
        /* clear flags for this operand */
        *dest_flg[x] = 0;
        /* ++ Copy flags from opcode table to CODE struct */
        *dest_flg[x] |= op_notes;

        /* ++ Handle operands hard-coded in the opcode [e.g. "dec eax"] */
        if ( operands[x] || op_flags[x] & OP_REG ) {
            /* operands[x] contains either an Immediate Value or a Register ID */
            *dest_buf[x] = operands[x];
            continue; /* next operand */
        }

        /* ++ Do Operand Type ++ */
        switch ( op_type) {
            /* This sets the operand Size based on the Intel Opcode Map
                * (Vol 2, Appendix A). Letter encodings are from section
                * A.1.2, 'Codes for Operand Type' */

            /* ------------------------ Operand Type ----------------- */
            case OPTYPE_c  :   /* byte or word [op size attr] */
                size = ( op_size == 4 ) ? 2 : 1;
                op_size_flag  = (op_size == 4) ? OP_WORD : OP_BYTE;
                break;
            case OPTYPE_a  :   /* 2 word or 2 DWORD [op size attr ] */
                /* when is this used? */
                size = ( op_size == 4 ) ? 4 : 2;
                op_size_flag  = (op_size == 4) ? OP_DWORD : OP_WORD;
                break;
            case OPTYPE_v  :   /* word or dword [op size attr] */
                size = ( op_size == 4 ) ? 4 : 2;
                op_size_flag  = (op_size == 4) ? OP_DWORD : OP_WORD;
                break;
            case OPTYPE_p  :   /* 32/48-bit ptr [op size attr] */
                size = ( op_size == 4 ) ? 6 : 4;
                op_size_flag  = (op_size == 4) ? OP_QWORD : OP_DWORD;
                break;
            case OPTYPE_b  :   /* byte, ignore op-size */
                size = 1;
                op_size_flag = OP_BYTE;
                break;
            case OPTYPE_w  :   /* word, ignore op-size */
                size = 2;
                op_size_flag = OP_WORD;
                break;
            case OPTYPE_d  :   /* dword , ignore op-size*/
                size = 4;
                op_size_flag = OP_DWORD;
                break;
            case OPTYPE_s  :   /* 6-byte psuedo-descriptor */
                size = 6;
                op_size_flag = OP_QWORD;
                break;
            case OPTYPE_q  :   /* qword, ignore op-size */
                size = 8;
                op_size_flag = OP_QWORD;
                break;
            case OPTYPE_dq  :   /* d-qword, ignore op-size */
            case OPTYPE_ps  :   /* 128-bit FP data */
            case OPTYPE_ss  :   /* Scalar elem of 128-bit FP data */
                size = 16;
                op_size_flag = OP_QWORD;
                break;
            case OPTYPE_pi  :   /* qword mmx register */
                break;
            case OPTYPE_si  :   /* dword integer register */
                break;
            case 0:
            default:
                /* ignore -- operand not used in this instruction */
                break;
        }

        /* override default register set based on size of Operand Type */
        /* this allows mixing of 8, 16, and 32 bit regs in instruction */
        if      ( size == 1 ) genRegs = REG_BYTE_OFFSET;
        else if ( size == 2 ) genRegs = REG_WORD_OFFSET;
        else                  genRegs = REG_DWORD_OFFSET;

        /* ++ Do Operand Addressing Method / Decode operand ++ */
        switch ( addr_meth ) {
            /* This sets the operand Size based on the Intel Opcode Map
                * (Vol 2, Appendix A). Letter encodings are from section
                * A.1.1, 'Codes for Addressing Method' */

            /* ---------------------- Addressing Method -------------- */
            /* Note that decoding mod ModR/M operand adjusts the size of
                * the instruction, but decoding the reg operand does not.
                * This should not cause any problems, as every 'reg' operand
                * has an associated 'mod' operand.
                *   dest_flg[x] points to a buffer for the flags of current operand
                *   dest_buf[x] points to a buffer for the value of current operand
                *   bytes is a running total of the instruction size
                * Goddamn-Intel-Note:
                *   Some Intel addressing methods [M, R] specify that the modR/M
                *   byte may only refer to a memory address or may only refer to
                *   a register -- however Intel provides no clues on what to do
                *   if, say, the modR/M for an M opcode decodes to a register
                *   rather than a memory address ... retuning 0 is out of the
                *   question, as this would be an Immediate or a RelOffset, so
                *   instead these modR/Ms are decoded according to opcode table.*/

            case ADDRMETH_E :   /* ModR/M present, Gen reg or memory  */
                bytes += DecodeModRM(buf,dest_buf[x], dest_flg[x], genRegs, size, MODRM_EA);
                *dest_flg[x] |= op_size_flag;
                apply_seg(prefix, dest_flg[x]);
                break;
            case ADDRMETH_M :   /* ModR/M only refers to memory */
                bytes += DecodeModRM(buf,dest_buf[x], dest_flg[x], genRegs, size, MODRM_EA);
                *dest_flg[x] |= op_size_flag;
                apply_seg(prefix, dest_flg[x]);
                break;
            case ADDRMETH_Q :   /* ModR/M present, MMX or Memory */
                bytes += DecodeModRM(buf,dest_buf[x], dest_flg[x], REG_MMX_OFFSET, size, MODRM_EA);
                *dest_flg[x] |= op_size_flag;
                apply_seg(prefix, dest_flg[x]);
                break;
            case ADDRMETH_R  :   /* ModR/M mod == gen reg */
                bytes += DecodeModRM(buf,dest_buf[x], dest_flg[x], genRegs,
                        size, MODRM_EA);
                *dest_flg[x] |= op_size_flag;
                apply_seg(prefix, dest_flg[x]);
                break;
            case ADDRMETH_W  :   /* ModR/M present, mem or SIMD reg */
                bytes += DecodeModRM(buf,dest_buf[x], dest_flg[x], REG_SIMD_OFFSET,
                        size, MODRM_EA);
                *dest_flg[x] |= op_size_flag;
                apply_seg(prefix, dest_flg[x]);
                break;

                /* MODRM -- reg operand */
                /* TODO: replace OP_REG with register type flags?? */
            case ADDRMETH_C  :   /* ModR/M reg == control reg */
                DecodeModRM(buf, dest_buf[x], dest_flg[x], REG_CTRL_OFFSET,
                        size, MODRM_reg);
                *dest_flg[x] |= op_size_flag;
                break;
            case ADDRMETH_D  :   /* ModR/M reg == debug reg */
                DecodeModRM(buf, dest_buf[x], dest_flg[x], REG_DEBUG_OFFSET,
                        size, MODRM_reg);
                *dest_flg[x] |= op_size_flag;
                break;
            case ADDRMETH_G  :   /* ModR/M reg == gen-purpose reg */
                DecodeModRM(buf, dest_buf[x], dest_flg[x], genRegs,
                        size, MODRM_reg);
                *dest_flg[x] |= op_size_flag;
                break;
            case ADDRMETH_P  :   /* ModR/M reg == qword MMX reg */
                DecodeModRM(buf, dest_buf[x], dest_flg[x], REG_MMX_OFFSET,
                        size, MODRM_reg);
                *dest_flg[x] |= op_size_flag;
                break;
            case ADDRMETH_S  :   /* ModR/M reg == segment reg */
                DecodeModRM(buf, dest_buf[x], dest_flg[x], REG_SEG_OFFSET,
                        size, MODRM_reg);
                *dest_flg[x] |= op_size_flag;
                break;
            case ADDRMETH_T  :   /* ModR/M reg == test reg */
                DecodeModRM(buf, dest_buf[x], dest_flg[x], REG_TEST_OFFSET,
                        size, MODRM_reg);
                *dest_flg[x] |= op_size_flag;
                break;
            case ADDRMETH_V  :   /* ModR/M reg == SIMD reg */
                DecodeModRM(buf, dest_buf[x], dest_flg[x], REG_SIMD_OFFSET,
                        size, MODRM_reg);
                *dest_flg[x] |= op_size_flag;
                break;

                /* No MODRM */
            case ADDRMETH_A  :   /* No modR/M -- direct addr */
                *dest_flg[x] |= OP_ADDR  | op_size_flag;
                GetSizedOperand(dest_buf[x], buf + bytes, size);
                apply_seg(prefix, dest_flg[x]);
                bytes += size;
                break;
            case ADDRMETH_F  :   /* EFLAGS register */
                *dest_flg[x] |= OP_REG | op_size_flag ;
                *dest_buf[x] = REG_FLAGS_INDEX;
                break;
            case ADDRMETH_I  :   /* Immediate val */
                *dest_flg[x] |= OP_IMM | OP_SIGNED  | op_size_flag;
                GetSizedOperand(dest_buf[x], buf + bytes, size);
                bytes += size;
                break;
            case ADDRMETH_J  :   /* Rel offset to add to IP [jmp] */
                *dest_flg[x] |= OP_REL | OP_SIGNED  | op_size_flag;
                GetSizedOperand(dest_buf[x], buf + bytes, size);
                bytes += size;
                break;
            case ADDRMETH_O  :   /* No ModR/M;operand is word/dword offset */
                /* NOTE: these are actually RVA's and not offsets to IP!!! */
                *dest_flg[x] |= OP_OFF | OP_SIGNED | op_size_flag;
                GetSizedOperand(dest_buf[x], buf + bytes, addr_size);
                apply_seg(prefix, dest_flg[x]);
                bytes += size;
                break;
            case ADDRMETH_X  :   /* Memory addressed by DS:SI [string!] */
                *dest_flg[x] |= OP_STRING | OP_REG  | op_size_flag;
                /* Set Operand to ID for register ESI */
                *dest_buf[x] = 6 + REG_DWORD_OFFSET;
                if ( prefix & PREFIX_REG_MASK)
                    apply_seg(prefix, dest_flg[x]);
                else
                    apply_seg(PREFIX_DS, dest_flg[x]);
                break;
            case ADDRMETH_Y  :   /* Memory addressed by ES:DI [string ] */
                *dest_flg[x] |= OP_STRING | OP_REG  | op_size_flag;
                /* Set Operand to ID for register EDI */
                *dest_buf[x] = 7 + REG_DWORD_OFFSET;
                if ( prefix & PREFIX_REG_MASK)
                    apply_seg(prefix, dest_flg[x]);
                else
                    apply_seg(PREFIX_ES, dest_flg[x]);
                break;

            case 0:            /* Operand is not used */
            default:
                /* ignore -- operand not used in this instruction */
                *dest_flg[x] = 0;
                break;
        }

    }   /* end foreach operand */

    return(bytes); /* return number of bytes in instruction */
}

// i changed it -- lcamtuf
int disasm_addr(const BYTE *buf, struct code *c, long rva){
    instr *t;         /* table in i386.opcode.map */
    int max;
    int off=0;
    int op,x;
    // int i;

    max=sizeof(tables86)/sizeof(asmtable)-1;

    // fprintf(stderr,"<%x %x %x %x> ",(int)buf[0],(int)buf[1],(int)buf[2],(int)buf[3]);

    // Skip prefixes.
    for ( x = 0; prefix_table[x][0] != 0; x++)
        if ((char)prefix_table[x][0] == (char)buf[0]) buf++;

    for (;max>=0;max--) {

        // fprintf(stderr,"[%d] cmp=%d b1=%x b2=%x  buf0=%x buf1=%x",max,tables86[max].cmp,
        // tables86[max].b1,tables86[max].b2,buf[0],buf[1]);

        off=tables86[max].cmp;

        t = tables86[max].table;

        if (off > 0)
            if ((unsigned char)buf[0] != (unsigned char)tables86[max].b1) continue;

        if (off == 2)
            if ((unsigned char)buf[1] != (unsigned char)tables86[max].b2) continue;

        op=((unsigned char)buf[off] / tables86[max].divisor)
            & (unsigned char)tables86[max].mask;

        // fprintf(stderr,"** passed checks, op=%d ** ",op);

        if (t[op].mnemonic[0]) {
            //      strcpy(c->mnemonic, t[op].mnemonic);
            strcpy(c->mnemonic, "invalid");
            if ( (unsigned char) tables86[max].mask == 0xFF) off++;
            x = InstDecode( &t[op], &buf[off], c, rva);
            return x+off+1;
        }
    }

    strcpy(c->mnemonic, "invalid");
    return 0;

}
