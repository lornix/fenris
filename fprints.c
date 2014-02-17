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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <libgen.h>
#include <fcntl.h>
#include <bfd.h>
//#include <libiberty.h>

#include "libfnprints.h"

#include "config.h"

void usage(const char *program_name)
{
    char *bname = basename((char *)program_name);
    fprintf(stderr, "Usage: %s [options] <elf_object>...\n", bname);
    fprintf(stderr, "\n");
    fprintf(stderr, "%s extracts digital fingerprints from the given ELF object(s)\n", bname);
    fprintf(stderr, "\n");
    fprintf(stderr, "    -f | --fancy    Display fancy output (it's not, really)\n");
    fprintf(stderr, "    -s | --strip    Remove leading _'s\n");
    fprintf(stderr, "    -h | --help     Display this usage info\n");
    exit(1);
}

/*
 * #define CODESEG (((unsigned int)buf) >> 24)
 */

int main(int argc, char *argv[])
{
    int i, f, size, symcnt, off;
    unsigned int fingerprint;
    int num_funcs = 0;
    int fancy_output = 0;
    int strip_names = 0;
    bfd *b;
    asymbol **syms;
    const int BUFSIZE = SIGNATSIZE + 4;
    unsigned char buf[BUFSIZE];
    char *nameptr;

    const char *short_options = "fsh";
    struct option long_options[] = {
        {"fancy", no_argument, NULL, 'f'},
        {"strip", no_argument, NULL, 's'},
        {"help",  no_argument, NULL, 'h'},
        {0,       no_argument, NULL, 0}
    };

    while ((i = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF) {
        switch (i) {
            case 'f':
                fancy_output = 1;
                break;
            case 's':
                strip_names = 1;
                break;
            case 'h':
            case '?':
                usage(argv[0]); /* never returns */
            default:
                break;
        }
    }

    if (optind >= argc) {
        usage(argv[0]); /* never returns */
        exit(1);
    }

    while (optind < argc) {
        b = bfd_openr(argv[optind++], 0);
        if (!b) {
            fprintf(stderr, "bfd_openr failed for '%s'\n", argv[optind - 1]);
            continue;
        }

        bfd_check_format(b, bfd_archive);
        bfd_check_format_matches(b, bfd_object, 0);

        if ((bfd_get_file_flags(b) & HAS_SYMS) == 0) {
            fprintf(stderr, (fancy_output) ? "EMPTY" : "No symbols.\n");
            continue;
        }

        size = bfd_get_symtab_upper_bound(b);
        syms = (asymbol **) malloc(size);
        symcnt = bfd_canonicalize_symtab(b, syms);

        for (i = 0; i < symcnt; ++i) {
            if (syms[i]->flags & BSF_FUNCTION) {
                nameptr = (char *)(bfd_asymbol_name(syms[i]));
                if (strip_names!=0) {
                    while (*nameptr == '_') {
                        nameptr++;
                    }
                }
                off = syms[i]->value;
                if (syms[i]->section) {
                    off += syms[i]->section->filepos;
                }

                f = open(argv[optind - 1], O_RDONLY);
                lseek(f, off, SEEK_SET);
                num_funcs++;
                bzero(buf, BUFSIZE);
                read(f, buf, SIGNATSIZE);
                fingerprint = fnprint_compute(buf, ((long int)buf >> 24));
                close(f);

                // Ignore only NOPs
                if (fingerprint != 0xA120AD5C) {
                    printf("[%s+%d] %s %08X\n", argv[optind - 1], off, nameptr, fingerprint);
                }
            }
        }

        if (fancy_output) {
            fprintf(stderr, "%d function%s", num_funcs, PLURAL(num_funcs, "s"));
        } else {
            fprintf(stderr, "[*] %s: (%d function%s)\n", argv[optind - 1], num_funcs, PLURAL(num_funcs, "s"));
        }
    }
    return 0;
}
