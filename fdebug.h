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

   Fenris debugger messages go here. Please refer to doc/debug-api.txt
   for more information.

*/

#ifndef _HAVE_FDEBUG_H
#define _HAVE_FDEBUG_H 1


#define DMSG_MAGIC1 	 0x0defaced
#define DMSG_MAGIC2	 0xdeadbeef

struct dmsg_header {
  unsigned int magic1;
  unsigned short type;
  int code_running; // Only responses.
  unsigned int magic2;
};

// Fenris responses:
#define DMSG_REPLY	1000	// Normal reply.
#define DMSG_ASYNC	2000	// Async data line follows.

// Debugger

#define DMSG_NOMESSAGE  0  // Don't send, just check for ASYNC
#define DMSG_GETMEM	2
#define DMSG_GETNAME	3
#define DMSG_GETADDR	4
#define DMSG_GETREGS	5
#define DMSG_SETREGS    6
#define DMSG_GETBACK	7
#define DMSG_DESCADDR   8
#define DMSG_DESCFD 	9
#define DMSG_ABREAK	10
#define DMSG_SBREAK	11
#define DMSG_IBREAK	12
#define DMSG_RWATCH	13
#define DMSG_WWATCH     14
#define DMSG_STEP	15
#define DMSG_TORET	16
#define DMSG_TOLIBCALL  17
#define DMSG_TOSYSCALL  18
#define DMSG_TOLOCALCALL 19
#define DMSG_TOLOWERNEST 20
#define DMSG_TONEXT	21
#define DMSG_RUN        22
#define DMSG_STOP	23
#define DMSG_FPRINT	24
#define DMSG_SETMEM	25
#define DMSG_LISTBREAK	26
#define DMSG_DEL	27
#define DMSG_GETMAP	29
#define DMSG_FDMAP	30
#define DMSG_SIGNALS	31
#define DMSG_KILL	32
#define DMSG_FOO        33
#define DMSG_FNLIST	34
#define DMSG_DYNAMIC	35
#define DMSG_HALT	36

#endif /* not _HAVE_FDEBUG_H */
