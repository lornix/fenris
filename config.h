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

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#define OUTBUF          (512*1024) // Output buffer size
#define SMALLOUT        512     // Output buffer for -o #
#define MAXNEST         256     // Max. function call nesting level.
// Must be even, better not to change it.
#define MFNN            64      // Max. in-function nest
#define MAXCHILDREN     64      // Traced child process table size.
#define MAXSYMBOLS      1024    // Max. number of cached library symbols.
#define MAXINDENT       32      // Max. visual indentation
#define TABINC          64      // Table increments
#define MAXNAME         64      // Max. function name
#define MAXFNAME        512     // Max. filename length to report
#define MAXDESCR        512     // Max. description length, line
#define MAXPDESC       4096     // Max. params description, total
#define MAXUNKNOWN       32     // Max. unknown text
#define MAXSIG           64     // Max. number of signals
#define SIGNATSIZE       24     // Size of function signature
#define MAXPARS          32     // Max libcall parameters.
#define MAXREP          512     // Max. number of -P options
#define FN_DBASE "fnprints.dat"
#define MAXCALLS     100000     // Max. calls, for 'dress'
#define MAXFENT       16000     // Max. entity length for Fenris <-> Aegir
#define MAXYSTR         256     // Max. string length for "y" command in A.
#define PROMPT   "[aegir] "     // Aegir prompt
#define MAXCMD          512     // Max. Aegir command length
#define MAXBREAK         64     // Max. breakpoints

#define PLURAL(s,r) (((s)==1)?"":r)

#define STDERRMSG(x...) fprintf(stderr,x)
#define FATALEXIT(x)    do { STDERRMSG("FATAL: %s\n",x); exit(1); } while (0);
#define PERROREXIT(x)   do { perror(x); exit(1); } while (0);

#define MAXMYSIG 31

#define MAG      "\\033[0;35m"
#define CYA      "\\033[0;36m"
#define NOR      "\\033[0;37m"
#define DAR      "\\033[1;30m"
#define RED      "\\033[1;31m"
#define GRE      "\\033[1;32m"
#define YEL      "\\033[1;33m"
#define BRI      "\\033[1;37m"


struct signed_user_regs_struct
{
  long long int r15;
  long long int r14;
  long long int r13;
  long long int r12;
  long long int rbp;
  long long int rbx;
  long long int r11;
  long long int r10;
  long long int r9;
  long long int r8;
  long long int rax;
  long long int rcx;
  long long int rdx;
  long long int rsi;
  long long int rdi;
  long long int orig_rax;
  long long int rip;
  long long int cs;
  long long int eflags;
  long long int rsp;
  long long int ss;
  long long int fs_base;
  long long int gs_base;
  long long int ds;
  long long int es;
  long long int fs;
  long long int gs;
};

#endif /* not _HAVE_CONFIG_H */
