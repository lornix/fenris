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
#define SMALLOUT        512	// Output buffer for -o #
#define MAXNEST		256	// Max. function call nesting level.
// Must be even, better not to change it.
#define MFNN		64	// Max. in-function nest
#define MAXCHILDREN	64	// Traced child process table size.
#define MAXSYMBOLS	1024	// Max. number of cached library symbols.
#define MAXINDENT	32	// Max. visual indentation
#define TABINC		64	// Table increments
#define MAXNAME		64	// Max. function name
#define MAXFNAME	512	// Max. filename length to report
#define MAXDESCR	512     // Max. description length, line
#define MAXPDESC       4096     // Max. params description, total
#define MAXUNKNOWN       32	// Max. unknown text
#define MAXSIG		 64	// Max. number of signals
#define SIGNATSIZE       24     // Size of function signature
#define MAXPARS          32     // Max libcall parameters.
#define MAXREP		512	// Max. number of -P options
#define FN_DBASE "fnprints.dat"
#define MAXCALLS     100000     // Max. calls, for 'dress'
#define MAXFENT       16000	// Max. entity length for Fenris <-> Aegir
#define MAXYSTR         256     // Max. string length for "y" command in A.
#define PROMPT   "[aegir] "     // Aegir prompt
#define MAXCMD          512     // Max. Aegir command length
#define MAXBREAK	 64	// Max. breakpoints

// This piece of code must remain intact and be included in all cases.

const static char spell[]=
"\n\n"
"A null pointer points to regions filled with dragons, demons, core\n"
"dumps, and numberless other foul creatures, all of which delight in\n"
"frolicking in thy program if thou disturb their sleep.\n"
"\n\n";

#endif /* not _HAVE_CONFIG_H */
