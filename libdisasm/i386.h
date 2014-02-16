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

extern int prefix_table[][2];

extern char *reg_dword[];
extern char *reg_word[];
extern char *reg_byte[];
extern char *reg_mmx[];
extern char *reg_simd[];
extern char *reg_debug[];
extern char *reg_control[];
extern char *reg_test[];
extern char *reg_seg[];
extern char *reg_fpu[];

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

extern int modrm_rm[];
extern int modrm_reg[];
extern int modrm_mod[];

struct SIB_byte {
    unsigned int scale : 2;
    unsigned int index : 3;
    unsigned int base  : 3;
};

extern int sib_scl[];
extern int sib_idx[];
extern int sib_bas[];

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
inline void InitRegTable( void );
inline int get_prologue(struct code **table);
inline int get_epilogue(struct code **table);
inline int GetSizedOperand( int *op, const BYTE *buf, int size);
inline int DecodeByte(BYTE b, struct modRM_byte *modrm);
inline int DecodeSIB(const BYTE *b);
inline int DecodeModRM(const BYTE *b, int *op, int *op_flags, int reg_type,
        int size, int flags);
inline int InstDecode( instr *t, const BYTE *buf, struct code *c, DWORD rva);
int disasm_addr(const BYTE *buf, struct code *c, long rva);

#include "i386-opcodes.h"

typedef struct x86_table {  //Assembly instruction tables
    instr *table;            //Pointer to table of instruction encodings
    char b1,b2;
    char cmp;
    char mask;               // bit mask for look up
    char minlim,maxlim;      // limits on min/max entries.
    char divisor;            // modrm byte position plus
} asmtable;

extern asmtable tables86[];

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
