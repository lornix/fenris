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

#ifndef _HAVE_OPDIS_H
#define _HAVE_OPDIS_H 1

#define DIS_NOTN_ATT    0
#define DIS_NOTN_INTEL  1

typedef int (*opdis_print_func) (FILE *stream, const char *format, ...);

typedef struct opdis_options
{
    opdis_print_func print_func;
    int notation;
}
opdis_options;

extern void opdis_init(opdis_options *opt);

extern void opdis_disass(FILE *stream, const char *buf, unsigned int addr, unsigned int len);
extern int opdis_disass_one(FILE *stream, const char *buf, unsigned int addr);
extern int opdis_getopsize(const char *buf, unsigned int addr);

#endif /* not _HAVE_OPDIS_H */
