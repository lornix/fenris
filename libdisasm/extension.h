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

#ifndef _HAVE_EXTENSION_H
#define _HAVE_EXTENSION_H

typedef void (*ext_init_fn)(void *);
typedef void (*ext_clean_fn)(void);
typedef int (*disfunc_fn)(unsigned char *, unsigned char, struct code *, long);
typedef int (*getcode_fn)(struct code **);

struct EXTENSION {
  char *filename;            /* name of extension file [full path] */
  int  flags;                /* uhh..... */
  void *lib;                 /* pointer to library */
  ext_init_fn fn_init;       /* init function for extension */
  ext_clean_fn fn_cleanup;   /* cleanup function for extension */
};


struct EXT__ARCH { 
  struct EXTENSION ext;
  int options;             // module-specific options

  int cpu_hi, cpu_lo;      // CPU high and low version numbers
  char endian,             // 0 = BIG, 1 = LITTLE
       sz_addr,            // Default Size of Address in Bytes
       sz_oper,            // Default Size of Operand in Bytes
       sz_inst,            // Default Size of Instruction in Bytes
       sz_byte,            // Size of Machine Byte in Bits
       sz_word,            // Size of Machine Word in Bytes
       sz_dword;           // Size of Machine DoubleWord in Bytes
  int SP,                  // RegID of Stack Pointer
      IP,                  // RegID of Instruction Pointer
      reg_gen,             // start of General regs in table
      reg_seg, reg_fp,     // start of seg, FPU regs in table
      reg_in, reg_out;     // start of procedure IN, OUT regs in table

  struct REGTBL_ENTRY *reg_table;
  int sz_regtable;
  unsigned char *reg_storage;

  disfunc_fn fn_disasm_addr;      // ptr to disassembly routine
  getcode_fn fn_get_prologue;     // WARNING From here down are considered   
  getcode_fn fn_get_epilogue;     //         "optional"  
};

#endif /* not _HAVE_EXTENSION_H */
