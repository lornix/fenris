/* 
   fenris - program execution path analysis tool
   ---------------------------------------------

   Copyright (C) 2001, 2002 by Bindview Corporation Portions copyright (C)
   2001, 2002 by their respective contributors Developed and maintained by
   Michal Zalewski <lcamtuf@coredump.cx>

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free 
   Software Foundation; either version 2 of the License, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
   for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   675 Mass Ave, Cambridge, MA 02139, USA.

 */

#ifndef _HAVE_FENRIS_H
#define _HAVE_FENRIS_H

#include "config.h"

struct fenris_mem {
    unsigned int addr,                 // Start addr of memory block (0 -
                                       // unused)
     len;                              // End addr of memory block
    int owner;                         // Owner ID (fnaddr[] offset), 0 -
                                       // main
    char auth;                         // size is authoritative?
    char *descr;                       // Human-readable description
    char *lasti;                       // Last input
};

struct fenris_fd {
    unsigned char special;             // socket or such?
    char *descr;                       // who opened and when?
    char *name;                        // filename?
    unsigned short p;                  // port?
};

struct fenris_map {
    char *name;                        // mapped filename
    char *descr;                       // map description (fd + creator)
    unsigned int addr;                 // start address
    unsigned int len;                  // map length
    char *lasti;                       // Last input
};

struct fenris_process {
    int pid,                           // process id
     nest;                             // call nesting level
    // FIXME: removed unsigned'ness from register vars
    struct signed_user_regs_struct pr; // saved regs (syscall)
    unsigned char atret,               // atret counter for prolog detection
     intercept,                        // delayed display_libcall() counter
     getname,                          // look for library function names
     anything,                         // did anything happen?
     Owarn,                            // optimization warning displayed?
     checkc2,                          // check for a result of c2 ret
     checka3,                          // check for a result of ff a3 jmp
     doret,                            // display \n on task exit
     jmplibc,                          // jmp into plt?
     donottouch,                       // pause PLT lookup detection
     is_static;                        // is it static?

    unsigned int cycles,               // statistics: cpu cycles
     fncalls,                          // statistics: local calls
     bopt, gopt,                       // statistics: good and bad pcnts
     libcalls,                         // statistics: libc calls
     syscalls,                         // statistics: syscalls
     ncalls,                           // normal calls, prolog detector check
     syscall,                          // waiting for given syscall to ret?
     lentry,                           // where did we enter PLT?
     curpcnt,                          // current parameter count (call)
     memtop,                           // mem[] top pointer
     idtop,                            // fnaddr[] top pointer
     fdtop,                            // fd[] top pointer
     mtop;                             // map[] top pointer

    unsigned char retpar;              // return clock

    unsigned char isfnct[MAXNEST];     // Is a local function?

    struct fenris_mem (*mem)[];        // memory region tracing dbase
    struct fenris_fd (*fd)[];          // file descriptor tracing dbase
    struct fenris_map (*map)[];        // linking map dbase
    unsigned int (*fnaddr)[];          // unique local functions list

    bfd *b;                            // BFD handle

    asymbol **syms;                    // BFD symtab
    unsigned int symcnt;               // symtab count
    unsigned char symfail;             // symbol table load failed?

    unsigned int fntop,                // top of function stacks
     fnid[MAXNEST],                    // function ID stack
     fnrip[MAXNEST],                   // function call rip
     frstart[MAXNEST],                 // function frame start stack
     frend[MAXNEST];                   // function frame end stack

    unsigned char *wlog[MAXNEST];      // function writelog stack

    char pstack[MAXNEST][MFNN];        // parameter count stacks
    int pst_top[MAXNEST];              // parameter count stack tops

    unsigned int lcpar[MAXPARS];       // libcall parameters
    unsigned char lcname[MAXNAME];     // libcall name
    unsigned int lcpcnt;               // old pcount

    unsigned int sh[MAXSIG];           // signal handlers
    char shret[MAXSIG];                // signal handler with leading ret?
    char justcalled;                   // just called a local fn?
    unsigned int signals;              // top signal?
    char syscalldone;                  // returning from sighandler?
};

#define debug(x...)     do { snprintf(verybigbuf,sizeof(verybigbuf)-1,x); fprintf(ostream,"%s",verybigbuf);  if (T_dostep) break_append(verybigbuf); } while (0)

#define AS_UINT(x)      (*((unsigned int*)&(x)))
#define AS_USHORT(x)    (*((unsigned short int*)&(x)))
#define AS_SSHORT(x)    (*((signed short int*)&(x)))

#define PRETTYSMALL     -1234567890

#define F_CARRY         1
#define F_PARITY        (1<<2)
#define F_AUX           (1<<4)
#define F_ZERO          (1<<6)
#define F_SIGN          (1<<7)
#define F_OVER          (1<<11)

#define FSET(f) ((r.eflags & (f)) == (f))

// This most likely shouldn't be hardcoded, but well. Should be
// good for now.
#define INLIBC(f) ((((f) >> 24) >= LIBCSEG) && (((f) >> 24) <= (LIBCSEG+5)))

#endif /* not _HAVE_FENRIS_H */
