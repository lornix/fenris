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

    The history of this file is pretty odd. The idea came from
    Marcin Gozdalik. The same day, I had a first version of this utility.
    A bit later, Marcin sent me his patches to make ELF modification
    capability work. Quite surprisingly, he did it with exactly the same
    starting code - derived from klog's code from Phrack 56 :-) Who
    should take credit for this file? Well, most certainly, it's all his
    fault :-)

    Special thanks for klog for making this a bit easier, libbfd docs
    are ugly.

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

#include "config.h"
#include "libfnprints.h"

#include <bfd.h>

#ifdef USE_OPENSSL
#include <openssl/md5.h>
#else
#include <md5global.h>
#include <md5.h>
#endif /* USE_OPENSSL */

char* lookfor=".text";
char* tofile;
int found;
int total;

MD5_CTX kuku;

struct symt {
    unsigned int addr;
    char* name;
};

struct symt sym[MAXSYMBOLS];
unsigned int symtop;

void copier(char* src,char* dst,char* secname);

void add_signature(int addr,char* name) {
    if (symtop>0 && sym[symtop-1].addr == (unsigned int)addr) {
        char buf[10000];
        sprintf(buf,"%s / %s",sym[symtop-1].name,name);
        free(sym[symtop-1].name);
        sym[symtop-1].name=strdup(buf);
    } else {
        sym[symtop].addr=addr;
        sym[symtop].name=strdup(name);
        symtop++;
        if (symtop>=MAXSYMBOLS) FATALEXIT("MAXSYMBOLS exceeded");
    }
    // printf("symbol %d: %s\n",symtop-1,sym[symtop-1].name);

}

unsigned char* code;

unsigned int calls[MAXCALLS];
unsigned int ctop;

/*
 * #define CODESEG (((unsigned int)calls) >> 24)
 */

inline void found_fnprint_file(int count __attribute__((unused)), struct fenris_fndb *cur, unsigned int fprint __attribute__((unused)), unsigned int addr)
{
    add_signature(addr, cur->name);
}

inline void found_fnprint(int count, struct fenris_fndb *cur, unsigned int fprint __attribute__((unused)), unsigned int addr)
{
    if (!count) printf("0x%08x: %s",addr,cur->name);
    else printf(", %s",cur->name);
}

inline void finish_fnprint(int count, unsigned int fprint __attribute__((unused)), int unused __attribute__((unused)))
{
    if (count) {
        found++;
        printf("\n");
    }
}

inline void finish_fnprint_file(int count, unsigned int fprint __attribute__((unused)), int unused __attribute__((unused)))
{
    if (count) found++;
}

int main(int argc,char* argv[]) {
    bfd* b;
    char opt;
    //FIXME: struct type mis-match?
    // struct sec* ss;
    struct bfd_section* ss;
    int fi;
    unsigned int i;

    bfd_init();

    STDERRMSG("dress - stripped binary recovery tool by <lcamtuf@coredump.cx>\n");

    while ((opt=getopt(argc,(void*)argv, "+S:F:"))!=EOF)
        switch(opt) {
            case 'F':
                if (load_fnbase(optarg) == -1)
                    STDERRMSG("* WARNING: cannot load '%s' fingerprints database.\n", optarg);
                break;

            case 'S':
                lookfor=optarg;
                break;

        }

    if (argc-optind<1 || argc-optind>2) {
        STDERRMSG("\nUsage: %s [ -S nnn ] [ -F nnn ] input_elf [ output_elf ]\n",argv[0]);
        STDERRMSG("  -S nnn     - use 'nnn' instead of default .text for code\n");
        STDERRMSG("  -F nnn     - use fingerprints from file 'nnn'\n\n");
        exit(1);
    }

    if (argc-optind==2) tofile=argv[optind+1];

    if (load_fnbase(FN_DBASE) == -1)
        STDERRMSG("* WARNING: cannot load '%s' fingerprints database.\n", FN_DBASE);
    if (!fnprints_count()) FATALEXIT("couldn't load any fingerprints (try -F)");

    b = bfd_openr(argv[optind],0);
    if (!b) {
        perror(argv[optind]);
        exit(1);
    }

    bfd_check_format(b,bfd_archive);
    if (!bfd_check_format_matches(b,bfd_object,0)) FATALEXIT("ELF format mismatch");

    if ((bfd_get_file_flags(b) & HAS_SYMS) != 0) {
        FATALEXIT("not a stripped binary.");
        exit(1);
    }

    //FIXME: strange, did this work before?
    ss=b->sections;

    while (ss) {
        if ((!ss->name) || (!strcmp(ss->name,lookfor))) break;
        ss=ss->next;
        if (!ss) FATALEXIT("cannot find code section (try -S).");
    }

    STDERRMSG("[+] Loaded %d fingerprints...\n",fnprints_count());

    STDERRMSG("[*] Code section at 0x%08x - 0x%08x, offset %d in the file.\n",
            (int)ss->vma,
            //FIXME: did this name change in 10 years?
            // (int)(bfd_get_start_address(b)+ss->_raw_size),
            (int)(bfd_get_start_address(b)+ss->rawsize),
            (int)ss->filepos);

    STDERRMSG("[*] For your initial breakpoint, use *0x%x\n",(int)ss->vma);

    fi=open(argv[optind],O_RDONLY);
    if (!fi) FATALEXIT("cannot open input file");
    //FIXME: did this name change in 10 years?
    // if (!(code=malloc(ss->_raw_size+5))) FATALEXIT("malloc failed");
    if (!(code=malloc(ss->rawsize+5))) FATALEXIT("malloc failed");
    lseek(fi,ss->filepos,SEEK_SET);
    //FIXME: did this name change in 10 years?
    // if (read(fi,code,ss->_raw_size)!=ss->_raw_size) FATALEXIT("read failed");
    if ((unsigned long int)read(fi,code,ss->rawsize)!=ss->rawsize) FATALEXIT("read failed");
    close(fi);

    STDERRMSG("[+] Locating CALLs... ");

    // This will catch many false positives, but who cares?
    //FIXME: did this name change in 10 years?
    // for (i=0;i<ss->_raw_size-5;i++) {
    for (i=0;i<ss->rawsize-5;i++) {
        if (code[i]==0xe8) {
            unsigned int a;
            unsigned int daddr;
            int got=0;
            int *off=(int*)&code[i+1];
            daddr=i+(*off)+5;
            //FIXME: did this name change in 10 years?
            // if (daddr > ss->_raw_size) continue; // Nah, stupid.
            if (daddr > ss->rawsize) continue; // Nah, stupid.
            for (a=0;a<ctop;a++) if (calls[a] == daddr) { got=1; break; } // Dupe.
            if (!got) {
                calls[ctop]=daddr;
                ctop++;
                if (ctop>=MAXCALLS) FATALEXIT("MAXCALLS exceeded");
            }
        }
    }

    STDERRMSG("%d found.\n",ctop);

    // For every call, calculate a signature, compare.

    STDERRMSG("[+] Matching fingerprints...\n");

    for (i=0;i<ctop;i++) {
        unsigned int r;
        unsigned char buf[SIGNATSIZE+4];

        memcpy(buf,&code[calls[i]],SIGNATSIZE);

        r = fnprint_compute(buf, (((unsigned long int)calls) >> 24));

        if (tofile)
            find_fnprints(r, found_fnprint_file, finish_fnprint_file, calls[i]);
        else
            find_fnprints(r, found_fnprint, finish_fnprint, calls[i]+ss->vma);

        total++;

    }

    bfd_close(b);
    if (tofile && found) copier(argv[optind],tofile,lookfor);

    STDERRMSG("[+] All set. Detected fingerprints for %d of %d functions.\n",found,total);

    return 0;
}

void copier(char* src,char* dst,char* secname) {

    //FIXME: another oddness with bfd
    //// struct sec* s;
    struct bfd_section* s;
    bfd *ibfd,*obfd;

    bfd_init();

    if (!strcmp(src,dst)) FATALEXIT("source and destination file can't be the same");
    STDERRMSG("[*] Writing new ELF file:\n");

    ibfd = bfd_openr(src,0);
    if (!ibfd) FATALEXIT("bfd_openr() on source file");
    obfd = bfd_openw(dst,"i586-pc-linux-gnulibc1");
    if (!obfd) FATALEXIT("bfd_openw() on destination file");
    if (!bfd_check_format_matches(ibfd, bfd_object, 0)) FATALEXIT("input ELF format problem");

    STDERRMSG("[+] Cloning general ELF data...\n");
    bfd_set_format (obfd, bfd_get_format(ibfd));
    bfd_set_start_address (obfd, bfd_get_start_address(ibfd));
    bfd_set_file_flags(obfd,(bfd_get_file_flags(ibfd) & bfd_applicable_file_flags(obfd)));
    bfd_set_arch_mach(obfd, bfd_get_arch (ibfd), bfd_get_mach (ibfd));

    s=ibfd->sections;

    STDERRMSG("[+] Setting up sections: ");

    while (s) {
        //FIXME: bfd name oddness?
        // struct sec* os;
        struct bfd_section* os;

        os=bfd_make_section_anyway(obfd,bfd_section_name(ibfd,s));
        if (s->name[0]=='.') STDERRMSG("%s ",bfd_section_name(ibfd,s));
        if (!os) FATALEXIT("can't create new section");

        bfd_set_section_size(obfd, os, bfd_section_size(ibfd,s));
        bfd_set_section_vma(obfd, os, bfd_section_vma (ibfd, s));
        bfd_set_section_flags(obfd, os, bfd_get_section_flags(ibfd,s));

        os->lma = s->lma;

        s->output_section = os;
        s->output_offset = 0;
        bfd_copy_private_section_data(ibfd, s, obfd, os);

        s=s->next;

    }

    STDERRMSG("\n");

    s=ibfd->sections;

    STDERRMSG("[+] Preparing new symbol tables...\n");

    {
        void* acopy;

        asymbol *ptrs[symtop+1];
        asymbol *news;
        unsigned int i;

        for (i=0;i<symtop;i++) {
            news = bfd_make_empty_symbol(obfd);
            news->name = sym[i].name;
            if (strlen(sym[i].name)>60) {
                sym[i].name[57]='.';
                sym[i].name[58]='.';
                sym[i].name[59]='.';
                sym[i].name[60]=0;
            }
            news->section = bfd_make_section_old_way(obfd,secname);
            news->flags = BSF_LOCAL|BSF_FUNCTION;
            news->value = sym[i].addr;
            // if (i>106 && i<113) printf("adding symbol %d: %s -> %x %s\n",i,sym[i].name,sym[i].addr,secname);
            ptrs[i] = news;
        }

        ptrs[symtop]=0;

        acopy=malloc(sizeof(ptrs));
        memcpy(acopy,ptrs,sizeof(ptrs));
        // It took me an hour to realize this ugly bastard does not create
        // a copy or process data immediately, but stores a pointer for
        // decades instead. Long live bfd docs!
        if (!bfd_set_symtab(obfd, acopy, symtop)) FATALEXIT("bfd_set_symtab failed");

    }

    STDERRMSG("[+] Copying all sections: ");

    while (s) {
        int siz;
        if (s->name[0]=='.') STDERRMSG("%s ",s->name);
        //FIXME: name change?
        // siz = bfd_get_section_size_before_reloc(s);
        siz = bfd_get_section_size(s);
        if (siz>=0)
            if (bfd_get_section_flags(ibfd, s) & SEC_HAS_CONTENTS) {
                void* memhunk = malloc(siz);
                if (!memhunk) FATALEXIT("malloc failed");
                if (!bfd_get_section_contents(ibfd, s, memhunk, 0, siz)) FATALEXIT("get_section contents failed");
                if (!bfd_set_section_contents(obfd, s->output_section, memhunk, 0, siz)) FATALEXIT("set_section_contents failed");
                free (memhunk);
            }

        s=s->next;
    }

    printf("\n");

    bfd_copy_private_bfd_data (ibfd, obfd);

    bfd_close(ibfd);
    bfd_close(obfd);

}
