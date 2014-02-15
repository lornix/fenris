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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <bfd.h>
//#include <libiberty.h>

#include "libfnprints.h"

#include "config.h"

unsigned char buf[SIGNATSIZE+4];

#define CODESEG (((unsigned int)buf) >> 24)

unsigned int result[4];
MD5_CTX kuku;

int main(int argc,char* argv[]) {
  int summ=0;
  asymbol** syms;
  int size,symcnt,i,off;
  bfd* b;

  if (argc-2) { 
    fprintf(stderr,"function signatures for fenris -- <lcamtuf@coredump.cx>\n");
    fprintf(stderr,"Usage: %s elf_object\n",argv[0]);
    exit(1);
  }

  b = bfd_openr(argv[1],0);
  if (!b) { fprintf(stderr,"bfd_openr failed\n"); exit(1); }

  bfd_check_format(b,bfd_archive);
  bfd_check_format_matches(b,bfd_object,0);

  if ((bfd_get_file_flags(b) & HAS_SYMS) == 0) {
    if (!getenv("FANCY")) fprintf(stderr,"No symbols.\n");
      else fprintf(stderr,"EMPTY");
    exit(1);
  }

  size=bfd_get_symtab_upper_bound(b);
  syms=(asymbol**)malloc(size);
  symcnt=bfd_canonicalize_symtab(b,syms);

  for (i=0;i<symcnt;i++) {

    if (syms[i]->flags & BSF_FUNCTION) {
      char name[500],*fiu;

      strcpy(name,(char*)(bfd_asymbol_name(syms[i])));
      if ((fiu=strstr(&name[2],"__"))) 
        if (*(fiu-1)!='_') *fiu=0;

      if ((fiu=strchr(name+1,'@'))) *fiu=0;

      if (!strlen(name)) continue;

      off=syms[i]->value; 
      if (syms[i]->section) off+=syms[i]->section->filepos;

      

      { unsigned int f;
        f=open(argv[1],O_RDONLY);
        lseek(f,off,SEEK_SET);
        summ++;
        bzero(buf,sizeof(buf));
        read(f,buf,SIGNATSIZE);

        f=fnprint_compute(buf,CODESEG);

        if (f!=0xA120AD5C) { // Ignore only NOPs
          printf("[%s+%d] %s ",argv[1],off,name);
          printf("%08X\n",f);
        }
      }
    }
  }

  if (getenv("FANCY")) fprintf(stderr,"%d function%s",summ,summ==1?"":"s");
  else fprintf(stderr,"--> %s: done (%d function%s)\n",argv[1],summ,
               summ==1?"":"s");

  return 0;

}
