/*
   fenris - program execution path analysis tool
   ---------------------------------------------

   Copyright (C) 2001, 2002 by Bindview Corporation
   Portions copyright (C) 2001, 2002 by their respective contributors
   Developed and maintained by Michal Zalewski <lcamtuf@coredump.cx>

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

#ifndef DIS_ASM_H
#define DIS_ASM_H

#include <stdio.h>
#include "bfd.h"

typedef int (*fprintf_ftype) PARAMS((PTR, const char*, ...));

typedef struct disassemble_info {
  fprintf_ftype fprintf_func;
  PTR stream;
  PTR application_data;
  PTR private_data;	/* For use by the disassembler. */
  int (*read_memory_func) PARAMS ((bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info));
  void (*memory_error_func) PARAMS ((int status, bfd_vma memaddr, struct disassemble_info *info));
  void (*print_address_func) PARAMS ((bfd_vma addr, struct disassemble_info *info));
  bfd_byte *buffer;
  bfd_vma buffer_vma;
  char *disassembler_options;
} disassemble_info;

extern int print_insn_i386 PARAMS ((bfd_vma, disassemble_info*));
extern int print_insn_i386_att PARAMS ((bfd_vma, disassemble_info*));
extern int print_insn_i386_intel PARAMS ((bfd_vma, disassemble_info*));

#endif /* ! defined (DIS_ASM_H) */
