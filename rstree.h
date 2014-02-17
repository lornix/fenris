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
/*

   An implementation of an ordered dictionary data structure, based
   on the randomized search trees (treaps) by Seidel and Aragon.

   'R. Seidel and C. R. Aragon. Randomized Binary Search Trees.
   Algorithmica, 16(4/5):464-497, 1996.'

   This structure implements an ordered dictionary that maps keys to values.
   Any non-zero integer can be used as a key and value.

   Most methods run in O(log n) randomized time,
   where n is the number of keys in the treap.

   This code is based on portions of libdict-0.2.0 library
   written by Farooq Mela <farooq@whatthefuck.com>.

   RSNode support by Przemyslaw Czerkas <pczerkas@mgmnet.pl> 29 July 2002.

 */
/*

   Copyright (C) 2001 Farooq Mela. All rights reserved.

   This software is distributed under the so-called ``Berkeley License.''

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
   3. All advertising materials mentioning features or use of this software
   must display the following acknowledgment:
   This product is developed by Farooq Mela.
   4. The name Farooq Mela may not be used to endorse or promote products
   derived from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY Farooq Mela ``AS IS'' AND ANY EXPRESS OR
   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL Farooq Mela BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
   OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef _HAVE_RSTREE_H
#define _HAVE_RSTREE_H

typedef struct _RSTree *RSTree;
typedef struct _RSNode *RSNode;

extern RSTree RSTree_create(void);
extern int RSTree_destroy(RSTree tr);

extern int RSTree_count(RSTree tr);
extern int RSTree_empty(RSTree tr);

extern RSNode RSTree_insert(RSTree tr, int key);
extern RSNode RSTree_put(RSTree    tr, int key);
extern RSNode RSTree_get(RSTree    tr, int key);
extern int    RSTree_remove(RSTree tr, int key);

extern int RSNode_get_key(RSTree tr, RSNode nd);
extern int RSNode_get_val(RSTree tr, RSNode nd);
extern int RSNode_set_val(RSTree tr, RSNode nd,  int val);

extern int RSTree_insert_val(RSTree tr, int key,  int val);
extern int RSTree_put_val(RSTree    tr, int key,  int val);
extern int RSTree_get_val(RSTree    tr, int key);

extern RSNode RSTree_first(RSTree tr);
extern RSNode RSTree_last(RSTree  tr);
extern RSNode RSTree_prev(RSTree  tr,  RSNode nd);
extern RSNode RSTree_next(RSTree  tr,  RSNode nd);

#endif /* not _HAVE_RSTREE_H */
