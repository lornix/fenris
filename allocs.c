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

   Here are my malloc() and realloc() versions that return cleared
   memory, plus do few other things, like tracking of buffers,
   return value checks.

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_ORIGINAL_ALLOCS
#include "allocs.h"

#ifdef DEBUG
#include "rstree.h"

RSTree allocs_tree;
int memop = 0;
#endif /* DEBUG */

allocs_error_handler_ftype global_error_handler;

void allocs_set_error_handler(allocs_error_handler_ftype handler)
{
    global_error_handler=handler;
}

void* original_malloc(const int size)
{
    return malloc(size);
}

void* original_realloc(void *r, const int size)
{
    return realloc(r, size);
}

void* original_strdup(const void *r)
{
    return strdup(r);
}

void original_free(void *r)
{
    return free(r);
}

void allocs_fatal(const char *msg)
{
    if (global_error_handler)
        global_error_handler(msg, 0);
    else {
        fprintf(stderr,"%s\n",msg);
        exit(1);
    }
}

char test_leaks;

#ifdef DEBUG

void allocs_atexit(void)
{
    RSNode nd;
    void *r;

    if (!test_leaks) return;

#ifdef DEBUG
    if (RSTree_count(allocs_tree) > 0) {
        int i=1;
        printf(">> Memory leaks: ");
        nd=RSTree_first(allocs_tree);
        while (nd) {
            r=(void *)RSNode_get_key(allocs_tree,nd);
            printf("[#%d %d \"%.20s\"] ",i,RSNode_get_val(allocs_tree,nd),(char *)r);
            original_free(r);
            nd=RSTree_next(allocs_tree,nd);
            i++;
        }
        printf("\n");
    } else
        printf(">> No memory leaks found (%d mem operations).\n",memop);
#endif /* DEBUG */

    RSTree_destroy(allocs_tree);
}

void register_atexit(void)
{
    int registered=0;

    if (!registered) {
        registered=1;
        if (atexit(allocs_atexit) == 0)
            allocs_tree=RSTree_create();
    }
}
#endif /* DEBUG */

void* my_malloc(const int size)
{
    void *ret;
    int siz;

    if (size <= 0)
        allocs_fatal("my_malloc size is <= 0");
    ret=original_malloc(size);
    if (!ret)
        allocs_fatal("malloc failed");
    bzero(ret, size);
    siz=malloc_usable_size(ret);
    if (size < siz)
        bzero(ret+size, siz-size);
#ifdef DEBUG
    register_atexit();
    RSTree_put_val(allocs_tree, (int)ret, siz);
    memop++;
#endif /* DEBUG */
    return ret;
}

void* my_realloc(void *r,const int size)
{
    void *ret;
    int oldsiz;

#ifdef DEBUG
    if (!r)
        return my_malloc(size);
    if (size == 0) {
        my_free(r);
        return 0;
    }
    register_atexit();
    if (!RSTree_remove(allocs_tree, (int)r))
        allocs_fatal("realloc on non-allocated memory");
#endif /* DEBUG */
    if (size < 0)
        allocs_fatal("my_realloc size is < 0");
    oldsiz=malloc_usable_size(r);
    ret=original_realloc(r, size);
    if (size != 0 && !ret)
        allocs_fatal("realloc failed");
    if (size > oldsiz)
        bzero(ret+oldsiz, size-oldsiz);
#ifdef DEBUG
    RSTree_put_val(allocs_tree, (int)ret, malloc_usable_size(ret));
    memop++;
#endif /* DEBUG */
    return ret;
}

void* my_strdup(const void *r)
{
    void *ret;

    ret=original_strdup(r);
    if (!ret)
        allocs_fatal("strdup failed");
#ifdef DEBUG
    register_atexit();
    RSTree_put_val(allocs_tree, (int)ret, malloc_usable_size(ret));
    memop++;
#endif /* DEBUG */
    return ret;
}

void my_free(void *r)
{
#ifdef DEBUG
    register_atexit();
    if (!RSTree_remove(allocs_tree, (int)r))
        allocs_fatal("free for non-allocated chunk");
    memop++;
#endif /* DEBUG */
    original_free(r);
}
