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

#include <stdarg.h>
#include "dis-asm.h"
#include "opdis.h"

static disassemble_info opdis_info;


/* callback */
static int read_memory(bfd_vma from, bfd_byte *to, unsigned int length, struct disassemble_info *info)
{
  memcpy(to, info->buffer + from - info->buffer_vma, length);
  return 0;
}


/* callback */
static void memory_error(int status, bfd_vma memaddr, struct disassemble_info *info)
{
  info->fprintf_func(info->stream, "Unknown error %d\n", status);
}


extern char* describe_address(unsigned int addr);

/* callback */
static void print_address(bfd_vma addr, struct disassemble_info *info)
{
  opdis_options *opt = (opdis_options *)info->application_data;
  char* x;
  
  switch (opt->notation) {
    case DIS_NOTN_ATT:
	info->fprintf_func(info->stream,"$0x%x",addr);
	break;
    case DIS_NOTN_INTEL:
	info->fprintf_func(info->stream,"0x%x",addr);
	break;
  };
  x = describe_address(addr);
  if (strlen(x)) 
    info->fprintf_func(info->stream," <%s>",x);
}


void opdis_init(opdis_options *opt)
{
  static char opt_str[64];
  
  opdis_info.fprintf_func = (fprintf_ftype)opt->print_func;
  opdis_info.stream = NULL;
  opdis_info.application_data = opt;
  opdis_info.private_data = NULL;
  opdis_info.read_memory_func = read_memory;
  opdis_info.memory_error_func = memory_error;
  opdis_info.print_address_func = print_address;

  /* options_str:
   *	[(i8086|i386|x86-64)]
   *	[,(att|intel)]
   *	[,(addr16|addr32)]
   *	[,(data16|data32)]
   *	[,suffix] <- always suffix operand size (att notation only)
   */

  sprintf(opt_str, "i386");
  switch (opt->notation) {
    case DIS_NOTN_ATT:
	strcat(opt_str, ",att");
	break;
    case DIS_NOTN_INTEL:
	strcat(opt_str, ",intel");
	break;
  };
  strcat(opt_str, ",addr32,data32");
  opdis_info.disassembler_options = opt_str;
}


static int disass_x86(unsigned int addr)
{
  char *x;
  int num;

  opdis_info.fprintf_func(opdis_info.stream, "%08x", addr);
  x = describe_address(addr);
  if (strlen(x))
    opdis_info.fprintf_func(opdis_info.stream, " [%s]",x);
  opdis_info.fprintf_func(opdis_info.stream, ": \t");
  num = print_insn_i386(addr, &opdis_info);
  opdis_info.fprintf_func(opdis_info.stream, "\n");
  return num;
}


void opdis_disass(FILE *stream, const char* buf, unsigned int addr, unsigned int len)
{
  int tmp_addr = addr;

  opdis_info.buffer = (char *)buf;
  opdis_info.buffer_vma = addr;
  opdis_info.stream = stream;
  while (tmp_addr<=addr+len) {
    tmp_addr += disass_x86(tmp_addr);
  }
}


int opdis_disass_one(FILE *stream, const char *buf, unsigned int addr)
{
  opdis_info.buffer = (char *)buf;
  opdis_info.buffer_vma = addr;
  opdis_info.stream = stream;
  return disass_x86(addr);
}


/* hack */
static int blind_fprintf(FILE *stream, char *format, ...)
{
  va_list args;

  va_start(args, format);
  va_end(args);
  return 0;
}


static void blind_print_address(bfd_vma addr, struct disassemble_info *info)
{
}


int opdis_getopsize(const char *buf, unsigned int addr)
{
  int num;
  fprintf_ftype save_fprintf_func;
  void *save_print_address_func;

  opdis_info.buffer = (char *)buf;
  opdis_info.buffer_vma = addr;

  /* save current funcs */
  save_fprintf_func = opdis_info.fprintf_func;
  save_print_address_func = opdis_info.print_address_func;

  /* new funcs */
  opdis_info.fprintf_func = (fprintf_ftype)blind_fprintf;
  opdis_info.print_address_func = blind_print_address;

  /* think */
  num = print_insn_i386(addr, &opdis_info);

  /* restore saved funcs */
  opdis_info.fprintf_func = save_fprintf_func;
  opdis_info.print_address_func = save_print_address_func;

  return num;
}

