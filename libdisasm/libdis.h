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

#ifndef _HAVE_LIBDIS_H
#define _HAVE_LIBDIS_H

struct changed  {
  char mnem[32];	// Mnemonic
  char size;		// Opcode size
  int addr;	        // Address
  unsigned int sc;	// Scale factor
  char areg[32];	// Address register
  char ireg[32];	// Index register

  // ( areg &&  addr && !ireg) : areg + addr
  // ( areg &&  addr &&  ireg) : areg + ireg * sc + addr
  // ( areg && !addr &&  ireg) : areg + ireg * sc
  // ( areg && !addr && !ireg) : areg
  // (!areg &&  addr && !ireg) : addr

  // recognize regs: eax, ebx, ecx, edx, esi, edi, esp, ebp

  // others do not make too much sense, I think.

};


struct changed* disassemble_address(const char*,const char);

#endif
