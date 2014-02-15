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


static instr tbl_Main[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x3 */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "add", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x5 */
{0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0 + REG_SEG_OFFSET, 0, 0},  /* 0x6 */
{0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 0 + REG_SEG_OFFSET, 0, 0},  /* 0x7 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0x8 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0x9 */
{ 0, INS_LOGIC, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0xA */
{ 0, INS_LOGIC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0xB */
{ 0, INS_LOGIC, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0xC */
{ 0, INS_LOGIC, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "or", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0xD */
{0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 1 + REG_SEG_OFFSET, 0, 0},  /* 0xE */
{1, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xF */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x10 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x11 */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x12 */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x13 */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x14 */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "adc", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x15 */
{0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 2 + REG_SEG_OFFSET, 0, 0},  /* 0x16 */
{0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 2 + REG_SEG_OFFSET, 0, 0},  /* 0x17 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x18 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x19 */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x1A */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x1B */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x1C */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sbb", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x1D */
{0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 3 + REG_SEG_OFFSET, 0, 0},  /* 0x1E */
{0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 3 + REG_SEG_OFFSET, 0, 0},  /* 0x1F */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x20 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x21 */
{ 0, INS_LOGIC, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x22 */
{ 0, INS_LOGIC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x23 */
{ 0, INS_LOGIC, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x24 */
{ 0, INS_LOGIC, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "and", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x25 */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x26 */
{0, INS_ARITH, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "daa", 0, 0, 0},  /* 0x27 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x28 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x29 */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x2A */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x2B */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x2C */
{ 0, INS_ARITH, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sub", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x2D */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x2E */
{0, INS_ARITH, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "das", 0, 0, 0},  /* 0x2F */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x30 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x31 */
{ 0, INS_LOGIC, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x32 */
{ 0, INS_LOGIC, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x33 */
{ 0, INS_LOGIC, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x34 */
{ 0, INS_LOGIC, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "xor", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x35 */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x36 */
{0, INS_ARITH, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "aaa", 0, 0, 0},  /* 0x37 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0},  /* 0x38 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0},  /* 0x39 */
{ 0, INS_FLAG, ADDRMETH_G | OPTYPE_b | OP_R, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0},  /* 0x3A */
{ 0, INS_FLAG, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0},  /* 0x3B */
{ 0, INS_FLAG, OP_REG | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x3C */
{ 0, INS_FLAG, OP_REG | OP_R, ADDRMETH_I | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "cmp", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x3D */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x3E */
{0, INS_ARITH, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "aas", 0, 0, 0},  /* 0x3F */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x40 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 1 + REG_DWORD_OFFSET, 0, 0},  /* 0x41 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0x42 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 3 + REG_DWORD_OFFSET, 0, 0},  /* 0x43 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 4 + REG_DWORD_OFFSET, 0, 0},  /* 0x44 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 5 + REG_DWORD_OFFSET, 0, 0},  /* 0x45 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 6 + REG_DWORD_OFFSET, 0, 0},  /* 0x46 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 7 + REG_DWORD_OFFSET, 0, 0},  /* 0x47 */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x48 */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 1 + REG_DWORD_OFFSET, 0, 0},  /* 0x49 */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0x4A */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 3 + REG_DWORD_OFFSET, 0, 0},  /* 0x4B */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 4 + REG_DWORD_OFFSET, 0, 0},  /* 0x4C */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 5 + REG_DWORD_OFFSET, 0, 0},  /* 0x4D */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 6 + REG_DWORD_OFFSET, 0, 0},  /* 0x4E */
{ 0, INS_ARITH, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 7 + REG_DWORD_OFFSET, 0, 0},  /* 0x4F */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x50 */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 1 + REG_DWORD_OFFSET, 0, 0},  /* 0x51 */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0x52 */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 3 + REG_DWORD_OFFSET, 0, 0},  /* 0x53 */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 4 + REG_DWORD_OFFSET, 0, 0},  /* 0x54 */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 5 + REG_DWORD_OFFSET, 0, 0},  /* 0x55 */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 6 + REG_DWORD_OFFSET, 0, 0},  /* 0x56 */
{ 0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 7 + REG_DWORD_OFFSET, 0, 0},  /* 0x57 */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x58 */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 1 + REG_DWORD_OFFSET, 0, 0},  /* 0x59 */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0x5A */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 3 + REG_DWORD_OFFSET, 0, 0},  /* 0x5B */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 4 + REG_DWORD_OFFSET, 0, 0},  /* 0x5C */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 5 + REG_DWORD_OFFSET, 0, 0},  /* 0x5D */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 6 + REG_DWORD_OFFSET, 0, 0},  /* 0x5E */
{ 0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 7 + REG_DWORD_OFFSET, 0, 0},  /* 0x5F */
{ 0, INS_STACK, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "pushad", 0, 0, 0},  /* 0x60 */
{ 0, INS_STACK, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "popad", 0, 0, 0},  /* 0x61 */
{ 0, INS_ARRAY, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_M | OPTYPE_a | OP_R, ARG_NONE, cpu_80386, "bound", 0, 0, 0},  /* 0x62 */
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ADDRMETH_G | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "arpl", 0, 0, 0},  /* 0x63 */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x64 */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x65 */ 
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x66 */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x67 */
{ 0, INS_STACK, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0, 0, 0},  /* 0x68 */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OP_R, cpu_80386, "imul", 0, 0, 0},  /* 0x69 */
{0, INS_STACK, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0, 0, 0},  /* 0x6A */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I |  OP_R, cpu_80386, "imul", 0, 0, 0},  /* 0x6B */
{0, INS_MOVE|INS_SYSTEM|INS_ARRAY,  ADDRMETH_Y | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "insb", 0, 2 + REG_DWORD_OFFSET, 0},  /* 0x6C */
{0, INS_MOVE|INS_SYSTEM|INS_ARRAY,  ADDRMETH_Y | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "insd", 0, 2 + REG_DWORD_OFFSET, 0},  /* 0x6D */
{0, INS_MOVE|INS_SYSTEM|INS_ARRAY,  OP_REG | OP_W, ADDRMETH_X | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "outsb", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0x6E */
{0, INS_MOVE|INS_SYSTEM|INS_ARRAY,  OP_REG | OP_W, ADDRMETH_X | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "outsb", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0x6F */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jo", 0, 0, 0},  /* 0x70 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jno", 0, 0, 0},  /* 0x71 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jc", 0, 0, 0},  /* 0x72 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnc", 0, 0, 0},  /* 0x73 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jz", 0, 0, 0},  /* 0x74 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnz", 0, 0, 0},  /* 0x75 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jbe", 0, 0, 0},  /* 0x76 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "ja", 0, 0, 0},  /* 0x77 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "js", 0, 0, 0},  /* 0x78 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jns", 0, 0, 0},  /* 0x79 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpe", 0, 0, 0},  /* 0x7A */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpo", 0, 0, 0},  /* 0x7B */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jl", 0, 0, 0},  /* 0x7C */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jge", 0, 0, 0},  /* 0x7D */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jle", 0, 0, 0},  /* 0x7E */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jg", 0, 0, 0},  /* 0x7F */
{2, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x80 */
{3, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x81 */
{4, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x82 */
{5, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x83 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0},  /* 0x84 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0},  /* 0x85 */
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80386, "xchg", 0, 0, 0},  /* 0x86 */
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_W, ARG_NONE, cpu_80386, "xchg", 0, 0, 0},  /* 0x87 */
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x88 */ // OPBYTE_b
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x89 */
{ 0, INS_MOVE, ADDRMETH_G | OPTYPE_b | OP_W, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x8A */
{ 0, INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x8B */
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_w | OP_W, ADDRMETH_S | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x8C */
{ 0, INS_PTR|INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_W, OPTYPE_d | ADDRMETH_M | OP_R, ARG_NONE, cpu_80386, "lea", 0, 0, 0},  /* 0x8D */ // lcamtuf
{ 0, INS_MOVE, ADDRMETH_S | OPTYPE_w | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x8E */
{ 0, INS_STACK, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 0, 0, 0},  /* 0x8F */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "nop", 0, 0, 0},  /* 0x90 */
{ 0, INS_MOVE, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", 0 + REG_DWORD_OFFSET, 1 + REG_DWORD_OFFSET, 0},  /* 0x91 */
{ 0, INS_MOVE, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", 0 + REG_DWORD_OFFSET, 2 + REG_DWORD_OFFSET, 0},  /* 0x92 */
{ 0, INS_MOVE, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", 0 + REG_DWORD_OFFSET, 3 + REG_DWORD_OFFSET, 0},  /* 0x93 */
{ 0, INS_MOVE, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", 0 + REG_DWORD_OFFSET, 4 + REG_DWORD_OFFSET, 0},  /* 0x94 */
{ 0, INS_MOVE, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", 0 + REG_DWORD_OFFSET, 5 + REG_DWORD_OFFSET, 0},  /* 0x95 */
{ 0, INS_MOVE, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", 0 + REG_DWORD_OFFSET, 6 + REG_DWORD_OFFSET, 0},  /* 0x96 */
{ 0, INS_MOVE, OP_REG | OP_W, OP_REG | OP_W, ARG_NONE, cpu_80386, "xchg", 0 + REG_DWORD_OFFSET, 7 + REG_DWORD_OFFSET, 0},  /* 0x97 */
{ 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cwde", 0, 0, 0},  /* 0x98 */
{ 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cdq", 0, 0, 0},  /* 0x99 */
{ 0, INS_SUB, ADDRMETH_A | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "callf", 0, 0, 0},  /* 0x9A */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "wait", 0, 0, 0},  /* 0x9B */
{ 0, INS_STACK, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "pushfd", 0, 0, 0},  /* 0x9C */
{ 0, INS_STACK|INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "popfd", 0, 0, 0},  /* 0x9D */
{0, INS_ARITH, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "sahf", 0, 0, 0},  /* 0x9E */
{0, INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lahf", 0, 0, 0},  /* 0x9F */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_O | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0xA0 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_O | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0xA1 */
{ 0, INS_MOVE, ADDRMETH_O | OPTYPE_d | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0 + REG_BYTE_OFFSET, 0},  /* 0xA2 */
{ 0, INS_MOVE, ADDRMETH_O | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0 + REG_DWORD_OFFSET, 0},  /* 0xA3 */
{0, INS_MOVE, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "movsb", 0, 0, 0},  /* 0xA4 */
{ 0, INS_MOVE, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "movsd", 0, 0, 0},  /* 0xA5 */
{0, INS_FLAG|INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cmpsb", 0, 0, 0},  /* 0xA6 */
{ 0, INS_FLAG|INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cmpsd", 0, 0, 0},  /* 0xA7 */
{ 0, INS_FLAG, OP_REG | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "test", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0xA8 */
{ 0, INS_FLAG, OP_REG | OP_R, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "test", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0xA9 */
{0, INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "stosb", 0, 0, 0},  /* 0xAA */
{ 0, INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "stosd", 0, 0, 0},  /* 0xAB */
{0, INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lodsb", 0, 0, 0},  /* 0xAC */
{ 0, INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lodsd", 0, 0, 0},  /* 0xAD */
{0, INS_FLAG|INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "scasb", 0, 0, 0},  /* 0xAE */
{ 0, INS_FLAG|INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "scasd", 0, 0, 0},  /* 0xAF */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0xB0 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 1 + REG_BYTE_OFFSET, 0, 0},  /* 0xB1 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 2 + REG_BYTE_OFFSET, 0, 0},  /* 0xB2 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 3 + REG_BYTE_OFFSET, 0, 0},  /* 0xB3 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 4 + REG_BYTE_OFFSET, 0, 0},  /* 0xB4 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 5 + REG_BYTE_OFFSET, 0, 0},  /* 0xB5 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 6 + REG_BYTE_OFFSET, 0, 0},  /* 0xB6 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 7 + REG_BYTE_OFFSET, 0, 0},  /* 0xB7 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0xB8 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 1 + REG_DWORD_OFFSET, 0, 0},  /* 0xB9 */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0xBA */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 3 + REG_DWORD_OFFSET, 0, 0},  /* 0xBB */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 4 + REG_DWORD_OFFSET, 0, 0},  /* 0xBC */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 5 + REG_DWORD_OFFSET, 0, 0},  /* 0xBD */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 6 + REG_DWORD_OFFSET, 0, 0},  /* 0xBE */
{ 0, INS_MOVE, OP_REG | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 7 + REG_DWORD_OFFSET, 0, 0},  /* 0xBF */
{6, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xC0 */
{7, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xC1 */
{ 0, INS_RET|INS_BRANCH, ADDRMETH_I | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "ret", 0, 0, 0},  /* 0xC2 */
{ 0, INS_RET|INS_BRANCH, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ret", 0, 0, 0},  /* 0xC3 */
{ 0, INS_PTR, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "les", 0, 0, 0},  /* 0xC4 */
{ 0, INS_PTR, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_M | OPTYPE_p | OP_R, ARG_NONE, cpu_80386, "lds", 0, 0, 0},  /* 0xC5 */
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0xC6 */ // OPTYPE_b
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0xC7 */ // lcamtuf v v
{ 0, INS_FRAME, ADDRMETH_I | OPTYPE_w | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "enter", 0, 0, 0},  /* 0xC8 */
{0, INS_FRAME, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "leave", 0, 0, 0},  /* 0xC9 */
{ 0, INS_RET|INS_BRANCH, ADDRMETH_I | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "retf", 0, 0, 0},  /* 0xCA */
{ 0, INS_RET|INS_BRANCH, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "retf", 0, 0, 0},  /* 0xCB */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "int3", 0, 0, 0},  /* 0xCC */
{ 0, INS_SYSTEM, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "int", 0, 0, 0},  /* 0xCD */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "into", 0, 0, 0},  /* 0xCE */
{ 0, INS_BRANCH|INS_RET|INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "iret", 0, 0, 0},  /* 0xCF */
{8, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xD0 */
{9, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xD1 */
{10, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xD2 */
{11, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xD3 */
{ 0, INS_ARITH, ADDRMETH_I | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "aam", 0, 0, 0},  /* 0xD4 */
{ 0, INS_ARITH, ADDRMETH_I | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "aad", 0, 0, 0},  /* 0xD5 */
{0, INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "setalc", 0, 0, 0},  /* 0xD6 */
{0, INS_ARRAY, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "xlat", 0, 0, 0},  /* 0xD7 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xD8 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xD9 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xDA */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xDB */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xDC */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xDD */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xDE */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xDF */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "loopnz", 0, 0, 0},  /* 0xE0 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "loopz", 0, 0, 0},  /* 0xE1 */
{ 0, INS_BRANCH, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "loop", 0, 0, 0},  /* 0xE2 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jcxz", 0, 0, 0},  /* 0xE3 */
{ 0, INS_MOVE|INS_SYSTEM, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "in", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0xE4 */
{ 0, INS_MOVE|INS_SYSTEM, OP_REG | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "in", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0xE5 */
{ 0, INS_MOVE|INS_SYSTEM, ADDRMETH_I | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", 0, 0 + REG_BYTE_OFFSET, 0},  /* 0xE6 */
{ 0, INS_MOVE|INS_SYSTEM, ADDRMETH_I | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", 0, 0 + REG_DWORD_OFFSET, 0},  /* 0xE7 */
{ 0, INS_SUB, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0},  /* 0xE8 */
{ 0, INS_BRANCH, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0},  /* 0xE9 */
{ 0, INS_BRANCH, ADDRMETH_A | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0},  /* 0xEA */
{ 0, INS_BRANCH, ADDRMETH_J | OPTYPE_b | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0},  /* 0xEB */
{0, INS_MOVE|INS_SYSTEM, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "in", 0 + REG_BYTE_OFFSET, 2 + REG_WORD_OFFSET, 0},  /* 0xEC */
{ 0, INS_MOVE|INS_SYSTEM, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "in", 0 + REG_DWORD_OFFSET, 2 + REG_WORD_OFFSET, 0},  /* 0xED */
{0, INS_MOVE|INS_SYSTEM, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", 2 + REG_WORD_OFFSET, 0 + REG_BYTE_OFFSET, 0},  /* 0xEE */
{ 0, INS_MOVE|INS_SYSTEM, OP_REG | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "out", 2 + REG_WORD_OFFSET, 0 + REG_DWORD_OFFSET, 0},  /* 0xEF */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "lock:", 0, 0, 0},  /* 0xF0 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "smi", 0, 0, 0},  /* 0xF1 */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "repne:", 0, 0, 0},  /* 0xF2 */
{ 0, INSTR_PREFIX, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "rep:", 0, 0, 0},  /* 0xF3 */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "hlt", 0, 0, 0},  /* 0xF4 */
{0, INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cmc", 0, 0, 0},  /* 0xF5 */
{12, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xF6 */
{13, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xF7 */
{0, INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "clc", 0, 0, 0},  /* 0xF8 */
{0, INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "stc", 0, 0, 0},  /* 0xF9 */
{0, INS_FLAG|INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cli", 0, 0, 0},  /* 0xFA */
{0, INS_FLAG|INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "sti", 0, 0, 0},  /* 0xFB */
{0, INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cld", 0, 0, 0},  /* 0xFC */
{0, INS_FLAG, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "std", 0, 0, 0},  /* 0xFD */
{14, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xFE */
{15, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0   } /* 0xFF */, 
};

static instr tbl_0F[] = {
{16, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x0 */
{17, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x1 */
{ 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lar", 0, 0, 0},  /* 0x2 */
{ 0, INS_SYSTEM, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, cpu_80386, "lsl", 0, 0, 0},  /* 0x3 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x4 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x5 */
{ 0, INS_FLAG|INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "clts", 0, 0, 0},  /* 0x6 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x7 */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "invd", 0, 0, 0},  /* 0x8 */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "wbinvd", 0, 0, 0},  /* 0x9 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "cflsh", 0, 0, 0},  /* 0xA */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud2", 0, 0, 0},  /* 0xB */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xC */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xD */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xE */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xF */
{ 0, INS_MOVE, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0},  /* 0x10 */
{ 0, INS_MOVE, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movups", 0, 0, 0},  /* 0x11 */
{ 0, INS_MOVE, ADDRMETH_W | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0},  /* 0x12 */
{ 0, INS_MOVE, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movlps", 0, 0, 0},  /* 0x13 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpcklps", 0, 0, 0},  /* 0x14 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "unpckhps", 0, 0, 0},  /* 0x15 */
{ 0, INS_MOVE, ADDRMETH_V | OPTYPE_q | OP_W, ADDRMETH_W | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0},  /* 0x16 */
{ 0, INS_MOVE, ADDRMETH_W | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movhps", 0, 0, 0},  /* 0x17 */
{19, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0x18 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x19 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1A */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1B */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1C */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1D */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1E */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1F */
{ 0, INS_MOVE, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_C | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x20 */
{ 0, INS_MOVE, ADDRMETH_R | OPTYPE_d | OP_W, ADDRMETH_D | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x21 */
{ 0, INS_MOVE, ADDRMETH_C | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x22 */
{ 0, INS_MOVE, ADDRMETH_D | OPTYPE_d | OP_W, ADDRMETH_R | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "mov", 0, 0, 0},  /* 0x23 */
{ 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x24 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x25 */
{ 0, INS_MOVE, ADDRMETH_I | OP_W, ADDRMETH_I | OP_R, ARG_NONE, cpu_80386|cpu_80486, "mov", 0, 0, 0},  /* 0x26 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x27 */
{ 0, INS_MOVE, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0},  /* 0x28 */
{ 0, INS_MOVE, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movaps", 0, 0, 0},  /* 0x29 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtpi2ps", 0, 0, 0},  /* 0x2A */
{ 0, INS_MOVE, ADDRMETH_W | OPTYPE_ps | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movntps", 0, 0, 0},  /* 0x2B */
{ 0, 0, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvttps2pi", 0, 0, 0},  /* 0x2C */
{ 0, 0, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "cvtps2pi", 0, 0, 0},  /* 0x2D */
{ 0, 0, ADDRMETH_V | OPTYPE_ss | OP_W, ADDRMETH_W | OPTYPE_ss | OP_R, ARG_NONE, cpu_PENTIUM2, "ucomiss", 0, 0, 0},  /* 0x2E */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ss | OP_W, ARG_NONE, cpu_PENTIUM2, "comiss", 0, 0, 0},  /* 0x2F */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "wrmsr", 0, 0, 0},  /* 0x30 */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdtsc", 0, 0, 0},  /* 0x31 */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM, "rdmsr", 0, 0, 0},  /* 0x32 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTPRO, "rdpmc", 0, 0, 0},  /* 0x33 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysenter", 0, 0, 0},  /* 0x34 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sysexit", 0, 0, 0},  /* 0x35 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x36 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x37 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x38 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x39 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3A */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3B */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3C */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3D */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3E */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3F */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovo", 0, 0, 0},  /* 0x40 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovno", 0, 0, 0},  /* 0x41 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovc", 0, 0, 0},  /* 0x42 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnc", 0, 0, 0},  /* 0x43 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovz", 0, 0, 0},  /* 0x44 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovnz", 0, 0, 0},  /* 0x45 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovbe", 0, 0, 0},  /* 0x46 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmova", 0, 0, 0},  /* 0x47 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovs", 0, 0, 0},  /* 0x48 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovns", 0, 0, 0},  /* 0x49 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpe", 0, 0, 0},  /* 0x4A */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovpo", 0, 0, 0},  /* 0x4B */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovl", 0, 0, 0},  /* 0x4C */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovge", 0, 0, 0},  /* 0x4D */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovle", 0, 0, 0},  /* 0x4E */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_PENTPRO, "cmovg", 0, 0, 0},  /* 0x4F */
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_V | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "movmskps", 0, 0, 0},  /* 0x50 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "sqrtps", 0, 0, 0},  /* 0x51 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rsqrtps", 0, 0, 0},  /* 0x52 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "rcpps", 0, 0, 0},  /* 0x53 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andps", 0, 0, 0},  /* 0x54 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "andnps", 0, 0, 0},  /* 0x55 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "orps", 0, 0, 0},  /* 0x56 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "xorps", 0, 0, 0},  /* 0x57 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "addps", 0, 0, 0},  /* 0x58 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_R, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "mulps", 0, 0, 0},  /* 0x59 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x5A */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x5B */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "subps", 0, 0, 0},  /* 0x5C */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "minps", 0, 0, 0},  /* 0x5D */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "divps", 0, 0, 0},  /* 0x5E */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ARG_NONE, cpu_PENTIUM2, "maxps", 0, 0, 0},  /* 0x5F */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklbw", 0, 0, 0},  /* 0x60 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpcklwd", 0, 0, 0},  /* 0x61 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckldq", 0, 0, 0},  /* 0x62 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "packsswb", 0, 0, 0},  /* 0x63 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtb", 0, 0, 0},  /* 0x64 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtw", 0, 0, 0},  /* 0x65 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpgtd", 0, 0, 0},  /* 0x66 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "packuswb", 0, 0, 0},  /* 0x67 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhbw", 0, 0, 0},  /* 0x68 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhwd", 0, 0, 0},  /* 0x69 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "punpckhdq", 0, 0, 0},  /* 0x6A */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "packssdw", 0, 0, 0},  /* 0x6B */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x6C */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x6D */
{ 0, INS_MOVE, ADDRMETH_P | OPTYPE_d | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0},  /* 0x6E */
{ 0, INS_MOVE, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0},  /* 0x6F */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ADDRMETH_I |  OPTYPE_b | OP_R, cpu_PENTIUM2, "pshuf", 0, 0, 0},  /* 0x70 */
{19, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0},  /* 0x71 */
{20, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0},  /* 0x72 */
{21, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0},  /* 0x73 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqb", 0, 0, 0},  /* 0x74 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqw", 0, 0, 0},  /* 0x75 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pcmpeqd", 0, 0, 0},  /* 0x76 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, "emms", 0, 0, 0},  /* 0x77 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x78 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x79 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x7A */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x7B */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x7C */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x7D */
{ 0, INS_MOVE, ADDRMETH_E | OPTYPE_d | OP_W, ADDRMETH_P | OPTYPE_d | OP_R, ARG_NONE, cpu_PENTMMX, "movd", 0, 0, 0},  /* 0x7E */
{ 0, INS_MOVE, ADDRMETH_Q | OPTYPE_q | OP_W, ADDRMETH_P | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "movq", 0, 0, 0},  /* 0x7F */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jo", 0, 0, 0},  /* 0x80 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jno", 0, 0, 0},  /* 0x81 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jc", 0, 0, 0},  /* 0x82 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnc", 0, 0, 0},  /* 0x83 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jz", 0, 0, 0},  /* 0x84 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jnz", 0, 0, 0},  /* 0x85 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jbe", 0, 0, 0},  /* 0x86 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "ja", 0, 0, 0},  /* 0x87 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "js", 0, 0, 0},  /* 0x88 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jns", 0, 0, 0},  /* 0x89 */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpe", 0, 0, 0},  /* 0x8A */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jpo", 0, 0, 0},  /* 0x8B */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jl", 0, 0, 0},  /* 0x8C */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jge", 0, 0, 0},  /* 0x8D */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jle", 0, 0, 0},  /* 0x8E */
{ 0, INS_COND, ADDRMETH_J | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jg", 0, 0, 0},  /* 0x8F */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seto", 0, 0, 0},  /* 0x90 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setno", 0, 0, 0},  /* 0x91 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setc", 0, 0, 0},  /* 0x92 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnc", 0, 0, 0},  /* 0x93 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setz", 0, 0, 0},  /* 0x94 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setnz", 0, 0, 0},  /* 0x95 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setbe", 0, 0, 0},  /* 0x96 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "seta", 0, 0, 0},  /* 0x97 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "sets", 0, 0, 0},  /* 0x98 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setns", 0, 0, 0},  /* 0x99 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpe", 0, 0, 0},  /* 0x9A */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setpo", 0, 0, 0},  /* 0x9B */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setl", 0, 0, 0},  /* 0x9C */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setge", 0, 0, 0},  /* 0x9D */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setle", 0, 0, 0},  /* 0x9E */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "setg", 0, 0, 0},  /* 0x9F */
{0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 4 + REG_SEG_OFFSET, 0, 0},  /* 0xA0 */
{0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 4 + REG_SEG_OFFSET, 0, 0},  /* 0xA1 */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80486, "cpuid", 0, 0, 0},  /* 0xA2 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bt", 0, 0, 0},  /* 0xA3 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shld", 0, 0, 0},  /* 0xA4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OP_R | OP_REG, cpu_80386, "shld", 0, 0, 1 + REG_BYTE_OFFSET}, /* 0xA5 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xA6 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xA7 */
{0, INS_STACK, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 5 + REG_SEG_OFFSET, 0, 0},  /* 0xA8 */
{0, INS_STACK, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "pop", 5 + REG_SEG_OFFSET, 0, 0},  /* 0xA9 */
{0, INS_SYSTEM, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "rsm", 0, 0, 0},  /* 0xAA */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0},  /* 0xAB */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_80386, "shrd", 0, 0, 0},  /* 0xAC */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_I | OP_R | OP_REG, cpu_80386, "shrd", 0, 0, 1 + REG_BYTE_OFFSET}, /* 0xAD */
{22, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 0, 0, 0, 0},  /* 0xAE */
{ 0, INS_ARITH, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "imul", 0, 0, 0},  /* 0xAF */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0},  /* 0xB0 */
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_G | OPTYPE_v | OP_W, ARG_NONE, cpu_80486, "cmpxchg", 0, 0, 0},  /* 0xB1 */
{ 0, INS_PTR, ADDRMETH_M | OPTYPE_p | OP_W, ADDRMETH_I | OP_R, ARG_NONE, cpu_80386, "lss", 0, 0, 0},  /* 0xB2 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0},  /* 0xB3 */
{ 0, INS_PTR, ADDRMETH_M | OPTYPE_p | OP_W, ADDRMETH_I | OP_R, ARG_NONE, cpu_80386, "lfs", 0, 0, 0},  /* 0xB4 */
{ 0, INS_PTR, ADDRMETH_M | OPTYPE_p | OP_W, ADDRMETH_I | OP_R, ARG_NONE, cpu_80386, "lgs", 0, 0, 0},  /* 0xB5 */
{ 0, INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0},  /* 0xB6 */ // lcamtufized
{ 0, INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "movzx", 0, 0, 0},  /* 0xB7 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xB8 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, "ud1", 0, 0, 0},  /* 0xB9 */
{23, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_80386, 0, 0, 0, 0},  /* 0xBA */
{ 0, INS_FLAG|INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_G | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0},  /* 0xBB */
{ 0, INS_FLAG, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsf", 0, 0, 0},  /* 0xBC */
{ 0, INS_FLAG, ADDRMETH_G | OPTYPE_v | OP_R, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "bsr", 0, 0, 0},  /* 0xBD */
{ 0, INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0},  /* 0xBE */
{ 0, INS_MOVE, ADDRMETH_G | OPTYPE_v | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ARG_NONE, cpu_80386, "movsx", 0, 0, 0},  /* 0xBF */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_G | OPTYPE_b | OP_W, ARG_NONE, cpu_80486, "xadd", 0, 0, 0},  /* 0xC0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "xadd", 0, 0, 0},  /* 0xC1 */
{24, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, 0, 0, 0, 0},  /* 0xC2 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xC3 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_E | OPTYPE_d | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pinsrw", 0, 0, 0},  /* 0xC4 */
{ 0, 0, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_P | OPTYPE_q | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "pextrw", 0, 0, 0},  /* 0xC5 */
{ 0, 0, ADDRMETH_V | OPTYPE_ps | OP_W, ADDRMETH_W | OPTYPE_ps | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, cpu_PENTIUM2, "shufps", 0, 0, 0},  /* 0xC6 */
{25, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, 0, 0, 0, 0},  /* 0xC7 */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0xC8 */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 1 + REG_DWORD_OFFSET, 0, 0},  /* 0xC9 */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 2 + REG_DWORD_OFFSET, 0, 0},  /* 0xCA */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 3 + REG_DWORD_OFFSET, 0, 0},  /* 0xCB */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 4 + REG_DWORD_OFFSET, 0, 0},  /* 0xCC */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 5 + REG_DWORD_OFFSET, 0, 0},  /* 0xCD */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 6 + REG_DWORD_OFFSET, 0, 0},  /* 0xCE */
{ 0, INS_MOVE, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_80486, "bswap", 7 + REG_DWORD_OFFSET, 0, 0},  /* 0xCF */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xD0 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0},  /* 0xD1 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0},  /* 0xD2 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0},  /* 0xD3 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xD4 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmullw", 0, 0, 0},  /* 0xD5 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xD6 */
{ 0, 0, ADDRMETH_G | OPTYPE_d | OP_W, ADDRMETH_P | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmovmskb", 0, 0, 0},  /* 0xD7 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusb", 0, 0, 0},  /* 0xD8 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubusw", 0, 0, 0},  /* 0xD9 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminub", 0, 0, 0},  /* 0xDA */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pand", 0, 0, 0},  /* 0xDB */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusb", 0, 0, 0},  /* 0xDC */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddusw", 0, 0, 0},  /* 0xDD */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxub", 0, 0, 0},  /* 0xDE */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pandn", 0, 0, 0},  /* 0xDF */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgb", 0, 0, 0},  /* 0xE0 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0},  /* 0xE1 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0},  /* 0xE2 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pavgw", 0, 0, 0},  /* 0xE3 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmulhuw", 0, 0, 0},  /* 0xE4 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmulhw", 0, 0, 0},  /* 0xE5 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xE6 */
{ 0, INS_MOVE, ADDRMETH_W | OPTYPE_q | OP_W, ADDRMETH_V | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "movntq", 0, 0, 0},  /* 0xE7 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsb", 0, 0, 0},  /* 0xE8 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubsw", 0, 0, 0},  /* 0xE9 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pminsw", 0, 0, 0},  /* 0xEA */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "por", 0, 0, 0},  /* 0xEB */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsb", 0, 0, 0},  /* 0xEC */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddsw", 0, 0, 0},  /* 0xED */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "pmaxsw", 0, 0, 0},  /* 0xEE */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pxor", 0, 0, 0},  /* 0xEF */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xF0 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0},  /* 0xF1 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0},  /* 0xF2 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0},  /* 0xF3 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xF4 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "pmaddwd", 0, 0, 0},  /* 0xF5 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTIUM2, "psadbw", 0, 0, 0},  /* 0xF6 */
{ 0, 0, ADDRMETH_P | OPTYPE_pi | OP_W, ADDRMETH_Q | OPTYPE_pi | OP_R, ARG_NONE, cpu_PENTIUM2, "maskmovq", 0, 0, 0},  /* 0xF7 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubb", 0, 0, 0},  /* 0xF8 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubw", 0, 0, 0},  /* 0xF9 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "psubd", 0, 0, 0},  /* 0xFA */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0xFB */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddb", 0, 0, 0},  /* 0xFC */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddw", 0, 0, 0},  /* 0xFD */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_Q | OPTYPE_q | OP_R, ARG_NONE, cpu_PENTMMX, "paddd", 0, 0, 0},  /* 0xFE */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   } /* 0xFF */, 
};

static instr tbl_0F00[] = {
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sldt", 0, 0, 0},  /* 0x0 */
{ 0, 0, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "str", 0, 0, 0},  /* 0x1 */
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lldt", 0, 0, 0},  /* 0x2 */
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "ltr", 0, 0, 0},  /* 0x3 */
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "verr", 0, 0, 0},  /* 0x4 */
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "verw", 0, 0, 0},  /* 0x5 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x6 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_0F01[] = {
{ 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sgdt", 0, 0, 0},  /* 0x0 */
{ 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "sidt", 0, 0, 0},  /* 0x1 */
{ 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lgdt", 0, 0, 0},  /* 0x2 */
{ 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_s | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lidt", 0, 0, 0},  /* 0x3 */
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "smsw", 0, 0, 0},  /* 0x4 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x5 */
{ 0, INS_SYSTEM, ADDRMETH_E | OPTYPE_w | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "lmsw", 0, 0, 0},  /* 0x6 */
{ 0, INS_SYSTEM, ADDRMETH_M | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80486, "invlpg", 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_0F18[] = {
{ 0, 0,  OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 0, 0, 0},  /* 0x0 */
{ 0, 0, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 0 + REG_TEST_OFFSET, 0, 0},  /* 0x1 */
{ 0, 0, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 1 + REG_TEST_OFFSET, 0, 0},  /* 0x2 */
{ 0, 0, OP_REG | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "prefetch", 2 + REG_TEST_OFFSET, 0, 0},  /* 0x3 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x4 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x5 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x6 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_0F71[] = {
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x0 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrlw", 0, 0, 0},  /* 0x2 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psraw", 0, 0, 0},  /* 0x4 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x5 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psllw", 0, 0, 0},  /* 0x6 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_0F72[] = {
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x0 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x1 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrld", 0, 0, 0},  /* 0x2 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x3 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrad", 0, 0, 0},  /* 0x4 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0},  /* 0x5 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "pslld", 0, 0, 0},  /* 0x6 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_0F73[] = {
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psrlq", 0, 0, 0},  /* 0x0 */
{ 0, 0, ADDRMETH_P | OPTYPE_q | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_PENTMMX, "psllq", 0, 0, 0   } /* 0x1 */, 
};

static instr tbl_0FAE[] = {
{ 0, INS_FPU, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, "fxsave", 0, 0, 0},  /* 0x0 */
{ 0, INS_FPU, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTMMX, "fxrstor", 0, 0, 0},  /* 0x1 */
{ 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "ldmxcsr", 0, 0, 0},  /* 0x2 */
{ 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "stmxcsr", 0, 0, 0},  /* 0x3 */
{ 0, 0, ARG_NONE, ARG_NONE, ARG_NONE, cpu_PENTIUM2, "sfence", 0, 0, 0   } /* 0x4 */, 
};

static instr tbl_0FBA[] = {
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "bt", 0, 0, 0},  /* 0x0 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "bts", 0, 0, 0},  /* 0x1 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "btr", 0, 0, 0},  /* 0x2 */
{ 0, INS_FLAG|INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "btc", 0, 0, 0   } /* 0x3 */, 
};

static instr tbl_0FC7[] = {
{ 0, INS_FLAG|INS_MOVE, ADDRMETH_M | OPTYPE_q | OP_W, ARG_NONE, ARG_NONE, cpu_PENTIUM, "cmpxch8b", 0, 0, 0   } /* 0x0 */, 
};

static instr tbl_80[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x0 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x3 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x5 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x6 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_b | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_81[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x0 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x3 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x5 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x6 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_82[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x0 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x3 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x5 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x6 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_83[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "add", 0, 0, 0},  /* 0x0 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "or", 0, 0, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "adc", 0, 0, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sbb", 0, 0, 0},  /* 0x3 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "and", 0, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sub", 0, 0, 0},  /* 0x5 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "xor", 0, 0, 0},  /* 0x6 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "cmp", 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_C0[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rol", 0, 0, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "ror", 0, 0, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 0, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 0, 0},  /* 0x3 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shl", 0, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shr", 0, 0, 0},  /* 0x5 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sal", 0, 0, 0},  /* 0x6 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sar", 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_C1[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rol", 0, 0, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "ror", 0, 0, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 0, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 0, 0},  /* 0x3 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shl", 0, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "shr", 0, 0, 0},  /* 0x5 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sal", 0, 0, 0},  /* 0x6 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "sar", 0, 0, 0   } /* 0x7 */, 
};

static instr tbl_D0[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "rol", 0, 1, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM  | OP_R, ARG_NONE, cpu_80386, "ror", 0, 1, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM  | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM  | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1, 0},  /* 0x3 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM  | OP_R, ARG_NONE, cpu_80386, "shl", 0, 1, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM  | OP_R, ARG_NONE, cpu_80386, "shr", 0, 1, 0},  /* 0x5 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM  | OP_R, ARG_NONE, cpu_80386, "sal", 0, 1, 0},  /* 0x6 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ADDRMETH_I | OP_IMM  | OP_R, ARG_NONE, cpu_80386, "sar", 0, 1, 0   } /* 0x7 */, 
};

static instr tbl_D1[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "rol", 0, 1, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "ror", 0, 1, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1, 0},  /* 0x3 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "shl", 0, 1, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "shr", 0, 1, 0},  /* 0x5 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "sal", 0, 1, 0},  /* 0x6 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ADDRMETH_I | OP_IMM | OP_R, ARG_NONE, cpu_80386, "sar", 0, 1, 0   } /* 0x7 */, 
};

static instr tbl_D2[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rol", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "ror", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x3 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shl", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shr", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x5 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sal", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x6 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sar", 0, 1 + REG_BYTE_OFFSET, 0   } /* 0x7 */, 
};

static instr tbl_D3[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rol", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "ror", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x1 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcl", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x2 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "rcr", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x3 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shl", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x4 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "shr", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x5 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sal", 0, 1 + REG_BYTE_OFFSET, 0},  /* 0x6 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, OP_REG | OP_R, ARG_NONE, cpu_80386, "sar", 0, 1 + REG_BYTE_OFFSET, 0   } /* 0x7 */, 
};

static instr tbl_F6[] = {
{ 0, INS_FLAG, ADDRMETH_I | OPTYPE_b | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0},  /* 0x0 */
{ 0, INS_FLAG, ADDRMETH_I | OPTYPE_b | OP_R, ADDRMETH_I | OPTYPE_b | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0},  /* 0x1 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "not", 0, 0, 0},  /* 0x2 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "neg", 0, 0, 0},  /* 0x3 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "mul", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "imul", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x5 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "div", 0 + REG_BYTE_OFFSET, 0, 0},  /* 0x6 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "idiv", 0 + REG_BYTE_OFFSET, 0, 0   } /* 0x7 */, 
};

static instr tbl_F7[] = {
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0},  /* 0x0 */
{ 0, INS_FLAG, ADDRMETH_E | OPTYPE_v | OP_R, ADDRMETH_I | OPTYPE_v | OP_R, ARG_NONE, cpu_80386, "test", 0, 0, 0},  /* 0x1 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "not", 0, 0, 0},  /* 0x2 */
{ 0, INS_LOGIC, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "neg", 0, 0, 0},  /* 0x3 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "mul", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x4 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "imul", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x5 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "div", 0 + REG_DWORD_OFFSET, 0, 0},  /* 0x6 */
{ 0, INS_ARITH, OP_REG | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "idiv", 0 + REG_DWORD_OFFSET, 0, 0   } /* 0x7 */, 
};

static instr tbl_FE[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 0, 0, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_b | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 0, 0, 0   } /* 0x1 */, 
};

static instr tbl_FF[] = {
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "inc", 0, 0, 0},  /* 0x0 */
{ 0, INS_ARITH, ADDRMETH_E | OPTYPE_v | OP_W, ARG_NONE, ARG_NONE, cpu_80386, "dec", 0, 0, 0},  /* 0x1 */
{ 0, INS_SUB, ADDRMETH_E | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0},  /* 0x2 */
{ 0, INS_SUB, ADDRMETH_E | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "call", 0, 0, 0},  /* 0x3 */
{ 0, INS_BRANCH, ADDRMETH_E | OPTYPE_v | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0},  /* 0x4 */
{ 0, INS_BRANCH, ADDRMETH_E | OPTYPE_p | OP_X, ARG_NONE, ARG_NONE, cpu_80386, "jmp", 0, 0, 0},  /* 0x5 */
{ 0, INS_STACK, ADDRMETH_E | OPTYPE_v | OP_R, ARG_NONE, ARG_NONE, cpu_80386, "push", 0, 0, 0},  /* 0x6 */
{0, 0, ARG_NONE, ARG_NONE, ARG_NONE, 0, 0, 0, 0, 0   } /* 0x7 */, 
};
