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

   The history of this file is pretty odd. The idea came from Marcin Gozdalik.
   The same day, I had a first version of this utility. A bit later, Marcin
   sent me his patches to make ELF modification capability work. Quite
   surprisingly, he did it with exactly the same starting code - derived from
   klog's code from Phrack 56 :-) Who should take credit for this file? Well,
   most certainly, it's all his fault :-)

   Special thanks for klog for making this a bit easier, libbfd docs are ugly.

   Some modifications and optimizations by Marcin Gozdalik.

 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>
#include <bfd.h>

#ifdef USE_OPENSSL
#include <openssl/md5.h>
#else
#include <md5global.h>
#include <md5.h>
#endif /* USE_OPENSSL */

#include "config.h"
#include "libfnprints.h"

char *lookfor=".text";
char *tofile;
int fnprint_found;
int total;

struct symt {
    unsigned int addr;
    char *name;
};

struct symt sym[MAXSYMBOLS];
unsigned int symtop;

void copier(char *src,char *dst,char *secname)
{
    struct bfd_section *s;
    bfd *ibfd,*obfd;
    void *acopy;
    asymbol *ptrs[symtop+1];
    asymbol *news;
    unsigned int i;
    bfd_init();
    if (!strcmp(src,dst)) {
        FATALEXIT("source and destination file can't be the same");
    }
    printf("[*] Writing new ELF file:\n");
    ibfd=bfd_openr(src,0);
    if (!ibfd) {
        FATALEXIT("bfd_openr() on source file");
    }
    obfd=bfd_openw(dst,"i586-pc-linux-gnulibc1");
    if (!obfd) {
        FATALEXIT("bfd_openw() on destination file");
    }
    if (!bfd_check_format_matches(ibfd,bfd_object,0)) {
        FATALEXIT("input ELF format problem");
    }
    printf("[+] Cloning general ELF data...\n");
    bfd_set_format(obfd,bfd_get_format(ibfd));
    bfd_set_start_address(obfd,bfd_get_start_address(ibfd));
    bfd_set_file_flags(obfd,(bfd_get_file_flags(ibfd) & bfd_applicable_file_flags(obfd)));
    bfd_set_arch_mach(obfd,bfd_get_arch(ibfd),bfd_get_mach(ibfd));
    s=ibfd->sections;
    printf("[+] Setting up sections: ");
    while (s) {
        struct bfd_section *os;
        os=bfd_make_section_anyway(obfd,bfd_section_name(ibfd,s));
        if (s->name[0]=='.')
            printf("%s ",bfd_section_name(ibfd,s));
        if (!os)
            FATALEXIT("can't create new section");
        bfd_set_section_size(obfd,os,bfd_section_size(ibfd,s));
        bfd_set_section_vma(obfd,os,bfd_section_vma(ibfd,s));
        bfd_set_section_flags(obfd,os,bfd_get_section_flags(ibfd,s));
        os->lma=s->lma;
        s->output_section=os;
        s->output_offset=0;
        bfd_copy_private_section_data(ibfd,s,obfd,os);
        s=s->next;
    }
    printf("\n");
    s=ibfd->sections;
    printf("[+] Preparing new symbol tables...\n");
    for (i=0; i<symtop; ++i) {
        news=bfd_make_empty_symbol(obfd);
        news->name=sym[i].name;
        //FIXME: add flag to not ellipse?
        if (strlen(sym[i].name) > 60) {
            sym[i].name[57]='.';
            sym[i].name[58]='.';
            sym[i].name[59]='.';
            sym[i].name[60]=0;
        }
        news->section=bfd_make_section_old_way(obfd,secname);
        news->flags=BSF_LOCAL|BSF_FUNCTION;
        news->value=sym[i].addr;
        // if (i>106 && i<113) printf("adding symbol %d: %s -> %x
        // %s\n",i,sym[i].name,sym[i].addr,secname);
        ptrs[i]=news;
        ptrs[symtop]=0;
        acopy=malloc(sizeof(ptrs));
        memcpy(acopy,ptrs,sizeof(ptrs));
        // It took me an hour to realize this ugly bastard does not create
        // a copy or process data immediately, but stores a pointer for
        // decades instead. Long live bfd docs!
        if (!bfd_set_symtab(obfd,acopy,symtop))
            FATALEXIT("bfd_set_symtab failed");
    }
    printf("[+] Copying all sections: ");
    while (s) {
        int siz;
        if (s->name[0]=='.') {
            printf("%s ",s->name);
        }
        siz=bfd_get_section_size(s);
        if (siz>=0) {
            if (bfd_get_section_flags(ibfd,s)&SEC_HAS_CONTENTS) {
                void *memhunk=malloc(siz);
                if (!memhunk) {
                    FATALEXIT("malloc failed");
                }
                if (!bfd_get_section_contents(ibfd,s,memhunk,0,siz)) {
                    FATALEXIT("get_section contents failed");
                }
                if (!bfd_set_section_contents(obfd,s->output_section,memhunk,0,siz)) {
                    FATALEXIT("set_section_contents failed");
                }
                free(memhunk);
            }
        }
        s=s->next;
    }
    printf("\n");
    bfd_copy_private_bfd_data(ibfd,obfd);
    bfd_close(ibfd);
    bfd_close(obfd);
}

void add_signature(int addr,char *name)
{
    char buf[10000+1];
    if (symtop>0 && sym[symtop-1].addr==(unsigned int)addr) {
        snprintf(buf,sizeof(buf)-1,"%s / %s",sym[symtop-1].name,name);
        free(sym[symtop-1].name);
        sym[symtop-1].name=strdup(buf);
    } else {
        sym[symtop].addr=addr;
        sym[symtop].name=strdup(name);
        symtop++;
        if (symtop>=MAXSYMBOLS) {
            FATALEXIT("MAXSYMBOLS exceeded");
        }
    }
    // printf("symbol %d: %s\n",symtop-1,sym[symtop-1].name);
}

unsigned char *code;
unsigned int calls[MAXCALLS];
unsigned int ctop=0;

void found_fnprint_file(int count __attribute__ ((unused)),
        struct fenris_fndb *cur,
        unsigned int fprint __attribute__ ((unused)),
        unsigned int addr)
{
    add_signature(addr,cur->name);
}

void found_fnprint(int count,
        struct fenris_fndb *cur,
        unsigned int fprint __attribute__ ((unused)),
        unsigned int addr)
{
    if (!count)
        printf("0x%08x: %s",addr,cur->name);
    else
        printf(", %s",cur->name);
}

void finish_fnprint(int count,
        unsigned int fprint __attribute__ ((unused)),
        int unused __attribute__ ((unused)))
{
    if (count) {
        fnprint_found++;
        printf("\n");
    }
}

void finish_fnprint_file(int count,
        unsigned int fprint __attribute__ ((unused)),
        int unused __attribute__ ((unused)))
{
    if (count) {
        fnprint_found++;
    }
}

int main(int argc,char *argv[])
{
    bfd *b;
    char opt;
    struct bfd_section *ss;
    int fi;
    unsigned int i;

    bfd_init();

    STDERRMSG("dress - stripped binary recovery tool by <lcamtuf@coredump.cx>\n");

    while ((opt=getopt(argc,(void *)argv,"s:f:"))!=EOF) {
        switch (opt) {
            case 'f':
                if (load_fnbase(optarg)==-1) {
                    STDERRMSG("* WARNING: cannot load '%s' fingerprints database.\n",optarg);
                }
                break;
            case 's':
                lookfor=strdup(optarg);
                break;
        }
    }
    if ((argc<=optind)||(argc-optind)>2) {
        STDERRMSG("\nUsage: %s [ -s nnn ] [ -f nnn ] input_elf [ output_elf ]\n",argv[0]);
        STDERRMSG("  -s nnn     - use 'nnn' instead of default .text for code\n");
        STDERRMSG("  -f nnn     - use fingerprints from file 'nnn'\n\n");
        exit(1);
    }
    if ((argc-optind)==2) {
        tofile=argv[optind+1];
    }

    if (load_fnbase(FN_DBASE)==-1) {
        STDERRMSG("* WARNING: cannot load '%s' fingerprints database.\n",FN_DBASE);
    }
    if (!fnprints_count()) {
        FATALEXIT("couldn't load any fingerprints (try -f)");
    }

    b=bfd_openr(argv[optind],0);
    if (!b) {
        perror(argv[optind]);
        exit(1);
    }

    bfd_check_format(b,bfd_archive);
    if (!bfd_check_format_matches(b,bfd_object,0)) {
        FATALEXIT("ELF format mismatch");
    }

    // if ((bfd_get_file_flags(b)&HAS_SYMS)!=0) {
    //     FATALEXIT("not a stripped binary.");
    // }

    ss=b->sections;
    while (ss) {
        if ((!ss->name)||(!strcmp(ss->name,lookfor))) {
            break;
        }
        ss=ss->next;
        if (!ss) {
            FATALEXIT("cannot find code section (try -S).");
        }
    }

    printf("[+] Loaded %d fingerprints...\n",fnprints_count());
    printf("[*] Code section at 0x%08x-0x%08x, offset %d (0x%x) in file.\n",
            (int)ss->vma,
            (int)(bfd_get_start_address(b)+ss->size),
            (int)ss->filepos,
            (int)ss->filepos);
    printf("[*] For your initial breakpoint, use *0x%x\n",(int)ss->vma);

    fi=open(argv[optind],O_RDONLY);
    if (!fi) {
        FATALEXIT("cannot open input file");
    }
    code=malloc(ss->size+5);
    if (!code) {
        FATALEXIT("malloc failed");
    }
    lseek(fi,ss->filepos,SEEK_SET);
    if ((unsigned long int)read(fi,code,ss->size)!=ss->size) {
        FATALEXIT("read failed");
    }
    close(fi);

    printf("[+] Locating CALLs... ");
    // This will catch many false positives, but who cares? (I do!)
    for (i=0; i<(ss->size-5); ++i) {
        if (code[i]==0xe8) {
            unsigned int a;
            unsigned int daddr;
            int found=0;
            int* off=(int*)&code[i+1];
            daddr=i+5+(*off);
            if (ss->size<daddr) {
                continue; /* way out of bounds */
            }
            for (a=0; a<ctop; ++a) {
                if (calls[a]==daddr) {
                    found=1;
                    break;
                }
            }
            if (!found) {
                calls[ctop]=daddr;
                ctop++;
                if (ctop>=MAXCALLS) {
                    FATALEXIT("MAXCALLS exceeded");
                }
            }
        }
    }
    printf("%d found.\n",ctop);
    // For every call, calculate a signature, compare.
    printf("[+] Matching fingerprints...\n");
    for (i=0; i<ctop; ++i) {
        unsigned int r;
        unsigned char buf[SIGNATSIZE+4];
        memcpy(buf,&code[calls[i]],SIGNATSIZE);
        r=fnprint_compute(buf);
        /* printf("%3d) %08X\n",i,r); */
        if (tofile) {
            find_fnprints(r,found_fnprint_file,finish_fnprint_file,calls[i]+ss->vma);
        } else {
            find_fnprints(r,found_fnprint,     finish_fnprint,     calls[i]+ss->vma);
        }
        total++;
    }
    bfd_close(b);
    if (tofile && fnprint_found) {
        copier(argv[optind],tofile,lookfor);
    }
    printf("[+] %s: Detected fingerprints for %d of %d functions.\n",argv[optind],fnprint_found,total);
    fflush(stdout);
    return 0;
}
