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
#include "bastard.h"
#include "extension.h"
#include "libdis.h"
#include "i386.h"

static struct addr_exp exp[3];
static struct EXT__ARCH ext_arch;
static int    inited;

static struct changed CH;
static unsigned int wantthis;

static inline void disassemble_init(void){
  ext_arch.options = 0;
  inited=1;
  ext_arch_init( &ext_arch );
}
   

static inline  char * get_reg_name(int index) {
   if (index >= ext_arch.sz_regtable) return 0;
   return ext_arch.reg_table[index].mnemonic;
}


static inline  void parse_addrexp(struct addr_exp *e){

  CH.sc=e->scale;

  if (AddrExp_IndexType(e->flags) == ADDREXP_REG)
    strcpy(CH.ireg,get_reg_name(e->index));

  if (AddrExp_BaseType(e->flags) == ADDREXP_REG)
    strcpy(CH.areg,get_reg_name(e->base));

  CH.addr=e->disp;

  return;

}


static inline  void handle_op(int op, int type){

   if (!(type & wantthis)) return;

   switch (type & OP_TYPE_MASK) {

      case OP_PTR:
      case OP_ADDR:
      case OP_OFF:  CH.addr=op; break;
      case OP_EXPR: parse_addrexp(&exp[op]); break;
      case OP_REG:  break;
      default:      if (wantthis == OP_W)
                    fprintf(stderr,"Ooops - handle_op(): type 0x%x,"
                    " no clue how to parse it!\n",type & OP_TYPE_MASK);

   }

}


struct changed* disassemble_address(const char *buf,const char wri) {
   int size;
   struct code c={};

   if (wri) wantthis=OP_W; else wantthis=OP_R;

   if (!inited) disassemble_init();

   bzero(exp,sizeof(exp));
   bzero(&CH,sizeof(CH));

   size=disasm_addr((char*)buf,&c,0);
   if (size>0) CH.size=size; else CH.size=1;

   if (wri) handle_op(c.dest, c.destType); else handle_op(c.src, c.srcType);
   handle_op(c.aux, c.auxType);

   if (CH.ireg[0] && !CH.sc) CH.sc=1;

//   if (CH.ireg[0] || CH.areg[0] || CH.addr)
//     fprintf(stderr,"Returning [%s] [%s]*%d %x, mnemonic '%s'\n",CH.areg,CH.ireg,CH.sc,CH.addr,c.mnemonic);

   strcpy(CH.mnem,c.mnemonic);

   return &CH;

}


int AddRegTableEntry( int index, char *name, int size){
   if (index >= ext_arch.sz_regtable) return 0;
   ext_arch.reg_table[index].size = size;
   strncpy(ext_arch.reg_table[index].mnemonic, name, 8);
   return(1);
}


int DefineAddrExp(int scale,int index,int base,int disp,int flags){
   int id;

   if (!exp[0].used) id = 0;
   else if (!exp[1].used) id = 1;
   else id = 2;
   
   exp[id].used  = 1;
   exp[id].scale = scale;
   exp[id].index = index;
   exp[id].base  = base;
   exp[id].disp  = disp;
   exp[id].flags = flags;

   return id;

}


