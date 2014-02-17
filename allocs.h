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

   This file was extracted from fenris.c by Marcin Gozdalik :-)
   Tree structure implementation by Przemys³aw Czerkas.

   Including allocs.h will automagically turn every malloc, realloc, free
   and strdup into my_malloc, my_realloc, my_free and my_strdup respectively
   you can override this by uncommenting the following line:
   #define USE_ORIGINAL_ALLOCS (but you don't want to do it for Fenris,
   otherwise, it'll break into tiny pieces and cut you badly).

 */

#ifndef _HAVE_ALLOCS_H
#define _HAVE_ALLOCS_H

#include <malloc.h>

typedef void (*allocs_error_handler_ftype) (const char *err_msg, int err_code);
void allocs_set_error_handler(allocs_error_handler_ftype handler);

void* my_malloc(const int size);
void* my_realloc(void *oldptr,const int size);
void* my_strdup(const void *r);
void my_free(void *r);

#ifndef USE_ORIGINAL_ALLOCS

#undef malloc
#undef realloc
#undef strdup
#undef free

#define malloc  my_malloc
#define realloc my_realloc
#define strdup  my_strdup
#define free    my_free

#endif /* not USE_ORIGINAL_ALLOCS */

#endif /* not _HAVE_ALLOCS_H */

