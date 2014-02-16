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

#ifndef _HAVE_I386_H
#define _HAVE_I386_H

#include "bastard.h"
#include "extension.h"

typedef struct INSTR {
    int  table,                   /* escape to this sub-table */
         mnemFlg,                 /* Flags referring to mnemonic */
         destFlg, srcFlg, auxFlg, /* ...and for specific operands */
         cpu;                     /* minimumCPU [AND with clocks?? */
    char mnemonic[16];            /* buffers for building instruction */
    int  dest, src, aux;
} instr;

#define INSTR_PREFIX      0xF0000000 /* arbitrary flag # :) */

#define PREFIX_LOCK       0x00100000
#define PREFIX_REPNZ      0x00200000
#define PREFIX_REPZ       0x00400000
#define PREFIX_REP        0x00800000
#define PREFIX_REP_SIMD   0x01000000
#define PREFIX_OP_SIZE    0x02000000
#define PREFIX_ADDR_SIZE  0x04000000
#define PREFIX_SIMD       0x08000000
#define PREFIX_CS         0x10000000
#define PREFIX_SS         0x20000000
#define PREFIX_DS         0x30000000
#define PREFIX_ES         0x40000000
#define PREFIX_FS         0x50000000
#define PREFIX_GS         0x60000000
#define PREFIX_REG_MASK   0xF0000000

static int prefix_table[][2] = {
    { 0xF0, PREFIX_LOCK },
    { 0xF2, PREFIX_REPNZ },
    { 0xF3, PREFIX_REP },
    { 0x2E, PREFIX_CS },
    { 0x36, PREFIX_SS},
    { 0x3E, PREFIX_DS},
    { 0x26, PREFIX_ES},
    { 0x64, PREFIX_FS},
    { 0x65, PREFIX_GS},
    { 0x66, PREFIX_OP_SIZE},
    { 0x67, PREFIX_ADDR_SIZE},
    //   { 0x0F, PREFIX_SIMD },
    { 0,    0}
};

static char *reg_dword[]   = {"eax",   "ecx",   "edx",   "ebx",   "esp",   "ebp",   "esi",   "edi"   };
static char *reg_word[]    = {"ax",    "cx",    "dx",    "bx",    "sp",    "bp",    "si",    "di"    };
static char *reg_byte[]    = {"al",    "cl",    "dl",    "bl",    "ah",    "ch",    "dh",    "bh"    };
static char *reg_mmx[]     = {"mm0",   "mm1",   "mm2",   "mm3",   "mm4",   "mm5",   "mm6",   "mm7"   };
static char *reg_simd[]    = {"xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7"  };
static char *reg_debug[]   = {"dr0",   "dr1",   "dr2",   "dr3",   "dr4",   "dr5",   "dr6",   "dr7"   };
static char *reg_control[] = {"cr0",   "cr1",   "cr2",   "cr3",   "cr4",   "cr5",   "cr6",   "cr7"   };
static char *reg_test[]    = {"tr0",   "tr1",   "tr2",   "tr3",   "tr4",   "tr5",   "tr6",   "tr7"   };
static char *reg_seg[]     = {"es",    "cs",    "ss",    "ds",    "fs",    "gs",    "",      ""      };
static char *reg_fpu[]     = {"st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)" };

#define ARG_NONE         0
#define cpu_8086         0x00001000
#define cpu_80286        0x00002000
#define cpu_80386        0x00003000
#define cpu_80486        0x00004000
#define cpu_PENTIUM      0x00005000
#define cpu_PENTPRO      0x00006000
#define cpu_PENTMMX      0x00007000
#define cpu_PENTIUM2     0x00008000

#define OPFLAGS_MASK     0x0000FFFF

#define ADDRMETH_MASK    0x00FF0000

#define ADDRMETH_A       0x00010000
#define ADDRMETH_C       0x00020000
#define ADDRMETH_D       0x00030000
#define ADDRMETH_E       0x00040000
#define ADDRMETH_F       0x00050000
#define ADDRMETH_G       0x00060000
#define ADDRMETH_I       0x00070000
#define ADDRMETH_J       0x00080000
#define ADDRMETH_M       0x00090000
#define ADDRMETH_O       0x000A0000
#define ADDRMETH_P       0x000B0000
#define ADDRMETH_Q       0x000C0000
#define ADDRMETH_R       0x000D0000
#define ADDRMETH_S       0x000E0000
#define ADDRMETH_T       0x000F0000
#define ADDRMETH_V       0x00100000
#define ADDRMETH_W       0x00110000
#define ADDRMETH_X       0x00120000
#define ADDRMETH_Y       0x00130000

#define OP_SIZE_8        0x00200000
#define OP_SIZE_16       0x00400000
#define OP_SIZE_32       0x00800000

#define OPTYPE_MASK      0x0F000000

#define OPTYPE_a         0x01000000
#define OPTYPE_b         0x02000000
#define OPTYPE_c         0x03000000
#define OPTYPE_d         0x04000000
#define OPTYPE_dq        0x05000000
#define OPTYPE_p         0x06000000
#define OPTYPE_pi        0x07000000
#define OPTYPE_ps        0x08000000
#define OPTYPE_q         0x09000000
#define OPTYPE_s         0x0A000000
#define OPTYPE_ss        0x0B000000
#define OPTYPE_si        0x0C000000
#define OPTYPE_v         0x0D000000
#define OPTYPE_w         0x0E000000

#define MODRM_EA         1
#define MODRM_reg        2

#define MODRM_RM_SIB     0x04
#define MODRM_RM_NOREG   0x05
#define MODRM_MOD_NODISP 0x00
#define MODRM_MOD_DISP8  0x01
#define MODRM_MOD_DISP32 0x02
#define MODRM_MOD_NOEA   0x03

#define SIB_INDEX_NONE   0x04
#define SIB_BASE_EBP     0x05
#define SIB_SCALE_NOBASE 0x00

struct modRM_byte {
    unsigned int mod : 2;
    unsigned int reg : 3;
    unsigned int rm  : 3;
};

static int modrm_rm[]  = {0, 1, 2, 3, MODRM_RM_SIB, MODRM_MOD_DISP32, 6, 7 };
static int modrm_reg[] = {0, 1, 2, 3, 4, 5, 6, 7 };
static int modrm_mod[] = {0, MODRM_MOD_DISP8, MODRM_MOD_DISP32, MODRM_MOD_NOEA };

struct SIB_byte {
    unsigned int scale : 2;
    unsigned int index : 3;
    unsigned int base  : 3;
};

static int sib_scl[] = {0, 2, 4, 8};
static int sib_idx[] = {0, 1, 2, 3, SIB_INDEX_NONE, 5, 6, 7 };
static int sib_bas[] = {0, 1, 2, 3, 4, SIB_SCALE_NOBASE, 6, 7 };

typedef unsigned char   BYTE;
typedef unsigned short  WORD;
typedef unsigned int    DWORD;

#define x86_MAIN 0
#define x86_0F   1
#define x86_80   2

#define REG_DWORD_OFFSET   0
#define REG_WORD_OFFSET    1  * 8
#define REG_BYTE_OFFSET    2  * 8
#define REG_MMX_OFFSET     3  * 8
#define REG_SIMD_OFFSET    4  * 8
#define REG_DEBUG_OFFSET   5  * 8
#define REG_CTRL_OFFSET    6  * 8
#define REG_TEST_OFFSET    7  * 8
#define REG_SEG_OFFSET     8  * 8
#define REG_FPU_OFFSET     9  * 8
#define REG_FLAGS_INDEX    10 * 8
#define REG_FPCTRL_INDEX   10 * 8 + 1
#define REG_FPSTATUS_INDEX 10 * 8 + 2
#define REG_FPTAG_INDEX    10 * 8 + 3
#define REG_EIP_INDEX      10 * 8 + 4
#define REG_IP_INDEX       10 * 8 + 5

#define REG_DWORD_SIZE    4
#define REG_WORD_SIZE     2
#define REG_BYTE_SIZE     1
#define REG_MMX_SIZE      4
#define REG_SIMD_SIZE     4
#define REG_DEBUG_SIZE    4
#define REG_CTRL_SIZE     4
#define REG_TEST_SIZE     4
#define REG_SEG_SIZE      2
#define REG_FPU_SIZE      10
#define REG_FLAGS_SIZE    4
#define REG_FPCTRL_SIZE   2
#define REG_FPSTATUS_SIZE 2
#define REG_FPTAG_SIZE    2
#define REG_EIP_SIZE      4
#define REG_IP_SIZE       2

void ext_arch_init( void *param);
static inline void InitRegTable( void );
static inline int get_prologue(struct code **table);
static inline int get_epilogue(struct code **table);
static inline int GetSizedOperand( int *op, BYTE *buf, int size);
static inline int DecodeByte(BYTE b, struct modRM_byte *modrm);
static inline int DecodeSIB(BYTE *b);
static inline int DecodeModRM(BYTE *b, int *op, int *op_flags, int reg_type,
        int size, int flags);
static inline int InstDecode( instr *t, BYTE *buf, struct code *c, DWORD rva);
int disasm_addr( BYTE *buf, struct code *c, long rva);

#include "i386-opcodes.h"

typedef struct x86_table {  //Assembly instruction tables
    instr *table;            //Pointer to table of instruction encodings
    char b1,b2;
    char cmp;
    char mask;               // bit mask for look up
    char minlim,maxlim;      // limits on min/max entries.
    char divisor;            // modrm byte position plus
} asmtable;

static asmtable tables86[]={
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

#define IGNORE_NULLS    0x01  /* don't disassemble sequences of > 4 NULLs */
#define MODE_16_BIT     0x02  /* use useless 16bit mode */

#define ISA_8086        0x10
#define ISA_80286       0x20
#define ISA_80386       0x40
#define ISA_80486       0x80
#define ISA_PENTIUM     0x100
#define ISA_PENTIUM_2   0x200
#define ISA_PENTIUM_3   0x400
#define ISA_PENTIUM_4   0x800
#define ISA_K6          0x1000
#define ISA_K7          0x2000
#define ISA_ATHLON      0x4000
#define ISA_SIMD        0x10000
#define ISA_MMX         0x20000
#define ISA_3DNOW       0x40000

struct REGTBL_ENTRY {
    int size;
    void *data;
    char mnemonic[8];
};

#endif /* not _HAVE_I386_H */
