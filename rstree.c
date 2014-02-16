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
   must display the following acknowledgement:
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

#include <stdlib.h>
#include <malloc.h>

#include "rstree.h"

typedef struct _RSNode
{
    int  key;
    int  value;
    int  prio;
    RSNode parent, left, right;
}
_RSNode;

typedef struct _RSTree
{
    RSNode root;
    int count;
}
_RSTree;

inline int compare_keys(int key1, int key2)
{
    if (key1 > key2)
        return 1;
    else if (key1 < key2)
        return -1;
    else
        return 0;
}

RSNode node_create(int key)
{
    RSNode nd = (RSNode) malloc(sizeof(_RSNode));

    nd->key    = key;
    nd->value  = 1; /* non-zero */
    nd->prio   = rand();
    nd->parent = NULL;
    nd->left   = NULL;
    nd->right  = NULL;

    return nd;
}

void node_rotate_left(RSTree tr, RSNode nd)
{
    RSNode right, parent;

    if (!tr || !nd || !nd->right)
        return;

    right = nd->right;
    nd->right = right->left;
    if (right->left)
        right->left->parent = nd;
    parent = nd->parent;
    right->parent = parent;
    if (parent) {
        if (parent->left == nd)
            parent->left = right;
        else
            parent->right = right;
    } else
        tr->root = right;
    right->left = nd;
    nd->parent = right;
}

void node_rotate_right(RSTree tr, RSNode nd)
{
    RSNode left, parent;

    if (!tr || !nd || !nd->left)
        return;

    left = nd->left;
    nd->left = left->right;
    if (left->right)
        left->right->parent = nd;
    parent = nd->parent;
    left->parent = parent;
    if (parent) {
        if (parent->left == nd)
            parent->left = left;
        else
            parent->right = left;
    } else
        tr->root = left;
    left->right = nd;
    nd->parent = left;
}

RSTree RSTree_create(void)
{
    RSTree tr = (RSTree) malloc(sizeof(_RSTree));

    tr->root  = NULL;
    tr->count = 0;

    return tr;
}

int RSTree_destroy(RSTree tr)
{
    int cnt;

    if (!tr)
        return 0;

    cnt = RSTree_empty(tr);
    free(tr);

    return cnt;
}

int RSTree_count(RSTree tr)
{
    if (!tr)
        return 0;

    return (tr->count);
}

int RSTree_empty(RSTree tr)
{
    RSNode nd, parent;
    int cnt;

    if (!tr)
        return 0;

    nd = tr->root;
    while (nd) {
        parent = nd->parent;
        if (nd->left || nd->right) {
            nd = nd->left ? nd->left : nd->right;
            continue;
        }

        free(nd);

        if (parent) {
            if (parent->left == nd)
                parent->left = NULL;
            else
                parent->right = NULL;
        }
        nd = parent;
    }

    tr->root = NULL;
    cnt = tr->count;
    tr->count = 0;

    return cnt;
}

RSNode RSTree_insert(RSTree tr, int key)
{
    int comp = 0;
    RSNode nd, parent = NULL;

    if (!tr || key == 0)
        return 0;

    nd = tr->root;
    while (nd) {
        comp = compare_keys(key, nd->key);
        if (comp == 0)
            return 0;
        parent = nd;
        nd = comp < 0 ? nd->left : nd->right;
    }

    nd = node_create(key);

    nd->parent = parent;
    if (!parent) {
        tr->root = nd;
        tr->count = 1;
        return nd;
    } else {
        if (comp < 0)
            parent->left = nd;
        else
            parent->right = nd;
    }
    tr->count++;

    while (parent) {
        if (parent->prio <= nd->prio)
            break;
        if (parent->left == nd)
            node_rotate_right(tr, parent);
        else
            node_rotate_left(tr, parent);
        parent = nd->parent;
    }

    return nd;
}

RSNode RSTree_put(RSTree tr, int key)
{
    int comp = 0;
    RSNode nd, parent = NULL;

    if (!tr || key == 0)
        return 0;

    nd = tr->root;
    while (nd) {
        comp = compare_keys(key, nd->key);
        if (comp == 0)
            return nd;
        parent = nd;
        nd = comp < 0 ? nd->left : nd->right;
    }

    nd = node_create(key);

    nd->parent = parent;
    if (!parent) {
        tr->root = nd;
        tr->count = 1;
        return nd;
    } else {
        if (comp < 0)
            parent->left = nd;
        else
            parent->right = nd;
    }
    tr->count++;

    while (parent) {
        if (parent->prio <= nd->prio)
            break;
        if (parent->left == nd)
            node_rotate_right(tr, parent);
        else
            node_rotate_left(tr, parent);
        parent = nd->parent;
    }

    return nd;
}

RSNode RSTree_get(RSTree tr, int key)
{
    int comp;
    RSNode nd;

    if (!tr || key == 0)
        return 0;

    nd = tr->root;
    while (nd) {
        comp = compare_keys(key, nd->key);
        if (comp == 0)
            break;
        nd = comp < 0 ? nd->left : nd->right;
    }

    return nd;
}

int RSTree_remove(RSTree tr, int key)
{
    int comp;
    RSNode nd, out, parent = NULL;
    int old_val;

    if (!tr || key == 0)
        return 0;

    nd = tr->root;
    while (nd) {
        comp = compare_keys(key, nd->key);
        if (comp == 0)
            break;
        parent = nd;
        nd = comp < 0 ? nd->left : nd->right;
    }

    if (!nd)
        return 0;

    while (nd->left && nd->right) {
        if (nd->left->prio < nd->right->prio)
            node_rotate_right(tr, nd);
        else
            node_rotate_left(tr, nd);
    }
    parent = nd->parent;
    out = nd->left ? nd->left : nd->right;
    if (out)
        out->parent = parent;
    if (parent) {
        if (parent->left == nd)
            parent->left = out;
        else
            parent->right = out;
    } else {
        tr->root = out;
    }

    old_val=nd->value;
    free(nd);
    tr->count--;

    return old_val;
}

int RSNode_get_key(RSTree tr, RSNode nd)
{
    if (!tr || !nd)
        return 0;

    return nd->key;
}

int RSNode_get_val(RSTree tr, RSNode nd)
{
    if (!tr || !nd)
        return 0;

    return nd->value;
}

int RSNode_set_val(RSTree tr, RSNode nd, int val)
{
    int old_val;

    if (!tr || !nd || val == 0)
        return 0;

    old_val = nd->value;
    nd->value=val;

    return old_val;
}

int RSTree_insert_val(RSTree tr, int key, int val)
{
    if (val == 0)
        return 0;

    return RSNode_set_val(tr, RSTree_insert(tr, key), val);
}

int RSTree_put_val(RSTree tr, int key, int val)
{
    if (val == 0)
        return 0;

    return RSNode_set_val(tr, RSTree_put(tr, key), val);
}

int RSTree_get_val(RSTree tr, int key)
{
    return RSNode_get_val(tr, RSTree_get(tr, key));
}

RSNode RSTree_first(RSTree tr)
{
    RSNode nd;

    if (!tr)
        return 0;

    if (!(nd = tr->root))
        return 0;

    for (; nd->left; nd = nd->left);

    return nd;
}

RSNode RSTree_last(RSTree tr)
{
    RSNode nd;

    if (!tr)
        return 0;

    if (!(nd = tr->root))
        return 0;

    for (; nd->right; nd = nd->right);

    return nd;
}

RSNode RSTree_prev(RSTree tr, RSNode nd)
{
    RSNode out;

    if (!tr || !nd)
        return 0;

    if (nd->left) {
        for (nd = nd->left; nd->right; nd = nd->right);
        return nd;
    }

    out = nd->parent;
    while (out && out->left == nd) {
        nd = out;
        out = out->parent;
    }

    return out;
}

RSNode RSTree_next(RSTree tr, RSNode nd)
{
    RSNode out;

    if (!tr || !nd)
        return 0;

    if (nd->right) {
        for (nd = nd->right; nd->left; nd = nd->left);
        return nd;
    }

    out = nd->parent;
    while (out && out->right == nd) {
        nd = out;
        out = out->parent;
    }

    return out;
}
