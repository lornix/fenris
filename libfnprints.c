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

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with 
   this program; if not, write to the Free Software Foundation, Inc., 675 Mass
   Ave, Cambridge, MA 02139, USA.

   Extracted from fenris.c by Marcin Gozdalik.

 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libfnprints.h"

struct fenris_fndb *fndb[256 * 256];   // Speed search table

int fnprint_count = 0;

/******************************
 * Load fingerprints database *
 ******************************/

int load_fnbase(const char *x)
{
    char buf[500];
    FILE *f;
    unsigned int a;

    f = fopen(x, "r");

    if (!f && !strchr(x, '/')) {
        snprintf(buf, 200, "%s/.fenris/%s", getenv("HOME"), x);
        f = fopen(buf, "r");
    }

    if (!f && !strchr(x, '/')) {
        snprintf(buf, 200, "/etc/%s", x);
        f = fopen(buf, "r");
    }

    if (!f && !strchr(x, '/')) {
        snprintf(buf, 200, "%s/%s", getenv("HOME"), x);
        f = fopen(buf, "r");
    }

    if (!f)
        return -1;

    // Now, this is going to be a bit awkward, but gives us great
    // benefit later, when searching. Use a table to lookup first two
    // bytes instantly, then compare two remaining bytes by searching
    // a linked list.

    while (fgets(buf, sizeof(buf) - 1, f)) {
        struct fenris_fndb ff;
        char *x, *fname;
        x = strchr(buf, ' ');
        if (!x)
            continue;                  // Doh?
        fname = x + 1;
        x = strchr(x + 1, ' ');
        if (!x)
            continue;                  // Doh?
        *x = 0;
        if (sscanf(x + 1, "%X", &a) != 1)
            continue;                  // Doh?!

        ff.a = a & 0xffff;
        ff.name = strdup(fname);
        ff.next = 0;

        if (!fndb[a >> 16]) {
            fndb[a >> 16] = malloc(sizeof(struct fenris_fndb));
            memcpy(fndb[a >> 16], &ff, sizeof(struct fenris_fndb));
        } else {
            struct fenris_fndb *dest = fndb[a >> 16];
            while (dest->next)
                dest = dest->next;
            dest->next = malloc(sizeof(struct fenris_fndb));
            memcpy(dest->next, &ff, sizeof(struct fenris_fndb));
        }

        fnprint_count++;
    }

    fclose(f);

    return (0);
}

int fnprints_count()
{
    return fnprint_count;
}

/* compute fingerprint for bytes given in sig codeseg is the code segment used
   to detect relocations sig has to be at last SIGNATSIZE+4 bytes long */

unsigned long fnprint_compute(unsigned char *sig, int codeseg)
{
    unsigned int result[4];
    MD5_CTX kuku;
    int i, tagme = 0;

    for (i = 2; i < SIGNATSIZE; i++) {
        // Three NOPs? That ain't no stinkin' code!
        if ((sig[i - 2] == 0x90) && (sig[i - 1] == 0x90) && (sig[i] == 0x90)) {
            sig[i - 2] = sig[i - 1] = 0;
            tagme = 1;
        }

        if (tagme)
            sig[i] = 0;
    }

    // I suck. TODO: parse relocs in signatures. For now,
    // just carefully exterminate anything interesting ;)
    for (i = 0; i < SIGNATSIZE; i++)
        if (sig[i] == codeseg)
            bzero(&sig[i - 3], 4);

    for (i = 0; i < SIGNATSIZE; i++)
        if (sig[i] == 0xe8)
            bzero(&sig[i + 1], 4);

    MD5_Init(&kuku);
    MD5_Update(&kuku, sig, SIGNATSIZE);
    MD5_Final((unsigned char *)result, &kuku);

    result[0] ^= result[2];
    result[1] ^= result[3];

    return (result[0] ^ result[1]);
}
