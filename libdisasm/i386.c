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
