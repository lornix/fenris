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

    Here are breakpoint handling routines and communication code needed
    to talk with Aegir or any other debugger. This file exists so that
    modification to Fenris can be minimized.

 */

#ifndef _HAVE_HOOKS_H
#define _HAVE_HOOKS_H 1

// Operating modes:
#define MODE_NONE       0       // Stop.
#define MODE_SINGLE     1       // Do single step[s]
#define MODE_RUN        2       // Run until break / exit
#define MODE_LIBCALL    3       // Continue to next libcall
#define MODE_CALL       4       // Continue to next local call
#define MODE_SYSCALL    5       // Continue to next syscall
#define MODE_NEST       6       // Continue to nest level change
#define MODE_RET        7       // Continue to ret[s]
#define MODE_LINE       8       // Continue to next line
#define MODE_DYN        9       // Go to dynamic.

// Connectivity management:
void break_listen(char* where,const char** argv);
void break_messenger(void);

// Specific handlers:
int  break_single(void);
void break_libcall(unsigned int addr);
void break_syscall(int num);
void break_call(unsigned int addr);
void break_ret(void);
void break_nestdown(void);
void break_signal(int signo);
void break_memread(unsigned int addr);
void break_memwrite(unsigned int addr);
void break_enterdyn(void);

void break_newline(void);
void break_append(char* fmt);
void break_exitcond(void);

int should_be_stopped(void);
void break_sendentity(void);
void break_sendentity_force(void);
void break_goaway(void);
void break_tellresumed(void);
void break_tellwillresume(int i);

#endif /* not _HAVE_HOOKS_H */
