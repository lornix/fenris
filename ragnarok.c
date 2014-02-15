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

   This file can be probably made two times shorter by separating
   appropriate functions from the code. But I coded it to handle
   single case, and later realized I have to handle two other, similar,
   so copy-and-paste was faster ;)

 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include "asmstring.h"
#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>

#include "config.h"
#include "html.h"

#define debug(x...)     fprintf(stderr,x)
#define outf(x...)      fprintf(outfile,x)
#define pfatal(y)       { if (y) perror(y); exit(1); }
#define fatal(x)        { debug("FATAL (line %d): %s\n",cline,x); exit(1); }

char  T_verb,T_domem;

#define MAXADDR 60000
#define MAXFNCT 3000

#define ST_FREE 0 // Free slot.
#define ST_CUR  1 // Currently present buffer.
#define ST_PAST 2 // Slot occupied by a discarded buffer.

#define BFL_ASSUMED 1 // Assumed buffer.

int nro_phase;

#define NRO doNRO()

inline char* doNRO(void) {
    nro_phase++;
    if (nro_phase % 2 )
        return NRO_1;
    else
        return NRO_2;
}

int topfd;

struct bufdesc {
    unsigned int iaddr;  // Initial parameters
    unsigned int isize;  // ...
    unsigned int addr;   // Address
    unsigned int size;   // Size
    unsigned char st;
    unsigned char yet;
    unsigned char fl;
    unsigned int num;
    unsigned int t;
};

int    cline;
struct bufdesc b[MAXADDR];
int    bynum[MAXADDR];
int    btop=-1,breally=0;
int    forcepid;
char   staticwarn;
char   progname[1026];
FILE*  outfile;
int    bnum;

char *my_file,*my_ptr,*my_end;

void my_open(const char* name) {
    struct stat st;
    int i;
    if (my_file) fatal("myfile already open");
    i=open(name,O_RDONLY);
    if (i<0) pfatal(name);
    if (fstat(i,&st)) pfatal("fstat on input");
    if (!(st.st_mode & S_IFREG)) fatal("input is not a regular file");
    if (st.st_size<=0) fatal("zero size input");
    my_file=mmap(0,st.st_size,PROT_READ,MAP_SHARED,i,0);
    if (my_file==MAP_FAILED) pfatal("mmap on input");
    my_end=my_file+st.st_size-1;
    my_ptr=my_file;
    close(i);
}

inline void my_seek(unsigned int off) {
    if (my_file+off > my_end) my_ptr=my_end; else my_ptr=my_file+off;
}

char* ofip;
char gnbuf[5000];

char* getname(char* what,int x) {
    sprintf(gnbuf,"%s:%s.rag:%d:%04d",ofip,what,getpid(),x);
    return gnbuf;
}

char getsbuf[1026];

inline char* my_gets(void) {
    char *x,*r=my_ptr;
    int add;

    if (my_ptr >= my_end - 1) return 0;

    if ((x=strchr(my_ptr,'\n'))) {
        // Overflow. Lala.
        strncpy(getsbuf,my_ptr,add=(x-my_ptr));
        getsbuf[add]=0;
        my_ptr=x+1;
    }

    if (my_ptr-r > 1000) fatal("next line too long");

    return getsbuf;

}

void usage(const char* whoami) {
    debug("Usage: %s trace_file output_file\n",whoami);
    exit(1);
}

void test_file(void) {
    char* buf;
    char type[10],ver[10];
    my_seek(0);
    if (!(buf=my_gets())) fatal("cannot read the header");
    if (sscanf(buf,"<<-- fenris [%8[A-Z]] %8[0-9.b]",type,ver)!=2)
        fatal("malformed file header");
    if (strcmp(type,"STD")) fatal("this is a non-standard file");
    if (strcmp(ver,VERSION)) fatal("version incompatibility");
    cline++;
    debug("[+] Input file checks passed.\n");
}

inline int find_inrange(unsigned int st,unsigned int end) {
    int i;

    // if (st >= end) fatal("st >= end in find_inrange");

    for (i=0;i<breally;i++)
        if (b[i].st == ST_CUR) {
            if (b[i].addr  >= st) // Starts in the range
                if (b[i].addr <= end)
                    return i;
            if (b[i].addr + b[i].size  >= st)
                if (b[i].addr + b[i].size <= end)
                    return i; // Ends in the range.
        }

    return -1;

}

inline int find_addr(unsigned int st) {
    int i;

    // for (i=0;i<breally;i++)
    //    debug("buf %d: %x:%d fl %d\n",i,b[i].addr,b[i].size,b[i].fl);

    for (i=0;i<breally;i++)
        if (b[i].st == ST_CUR) {
            if (b[i].addr  <= st)
                if ((b[i].addr + b[i].size) > st) {
                    //          debug("Find addr %x returning %d (%x to %x)\n",st,i,b[i].addr,b[i].addr+b[i].size);
                    return i;
                }
        }

    return -1;

}

inline int findbynum(int n) {
    return bynum[n];
}

int bufno=0;

void get_buffers(void) {
    char *x,*y;
    unsigned int addr;
    int len;
    int q,i,left,over;
    int problems=0;
    int exitcond=0;
    char pidnotice=0;
    char hadstar=0;

    debug("*** PHASE 1: Preliminary analysis and buffer layout...\n");

    while ((x=my_gets())) {
        cline++;

        { char *spa,*naw,*dwu;
            // Skip EIP!
            if ((spa=strchr(x,' ')))
                if ((naw=strchr(x,']')))
                    if ((dwu=strchr(x,':')))
                        if ((spa>naw) && (naw<dwu) && (spa<dwu)) x=spa+1;
        }

        if (!strncmp(x,"+++ Executing '",15)) {
            char* w;
            int tracepid;
            x+=15;
            if (!(w=strrchr(x,'\''))) fatal("malformed exec");
            *w=0;
            sscanf(w+1," (pid %d",&tracepid);
            debug("[+] Target locked: pid %d, command '%s'\n",tracepid,x);
            forcepid=tracepid;
            strncpy(progname,x,1024);
            if (strstr(w+1,"static")) {
                debug("[!] Warning: this is a static application, I'm not too good at it!\n");
                staticwarn=1;
            }
        } else

            if (!strncmp(x,"+++ Process ",11) && strstr(x,"image replaced")) {
                int miau;
                sscanf(x+11,"%d",&miau);
                if (miau==forcepid) {
                    debug("[!] Will not trace pid %d after execve, bailing out.\n",miau);
                    goto bailout;
                }
                continue;
            }

        { int miau;
            if (sscanf(x,"%d:",&miau)==1) {
                if (forcepid!=miau) {
                    if (!pidnotice) debug("[!] Only first process analyzed (%d but not %d or others).\n",forcepid,miau);
                    pidnotice=1;
                    continue;
                }
            }
        }

        if (!(cline % 941))
            debug("[+] Collecting data... %0.02f%% (%d lines) done\r", ((float)(my_ptr-my_file)) * 100.0 / ((float)(my_end-my_file)),cline);

        if (x[0]=='>') {
            if (strstr(x,"more processes")) exitcond=1; else {
                problems++;
                debug("[!] line %d: trace error: %s\n",cline,x+2);
            }
        }

        if (x[0]=='*') {
            if (!T_domem) if (strstr(x,"strange")) continue;
            if (!hadstar) problems++;
            if (x[1]=='*') hadstar=!hadstar;
            debug("[!] line %d: %s\n",cline,x);
            continue;
        } else hadstar=0;

        if (btop<0) {
            int i;
            bufno++;
            for (i=0;i<breally;i++) if (b[i].st == ST_FREE) break;
            if (i==breally) {
                breally++;
                if (breally>=MAXADDR) fatal("MAXADDR exceeded");
            }
            btop=i;
        }

        if (!(y=strchr(x,' '))) continue;
        x=y;
        while (*x==' ') x++;

        //    debug("# btop=%d br=%d Parsing line: %s\n",btop,breally,x);

        if (!strncmp(x,"\\ UNEXPECTED",12)) {
            debug("[!] line %d: unexpected %s\n",cline,x+13);
            x+=11; *x='\\'; problems++;
        }

        if (!strncmp(x,"\\ new",5)) {
            // Check for collisions, add new buffer.
            // \ new [authoritative] buffer candidate: %x:%d (%s)
            if (!strstr(x,"buffer candidate:")) continue;
            if (!(x=strchr(x,':'))) fatal("malformed \\ new line");
            x+=1;
            if (sscanf(x," %x:%d",&addr,&len)!=2) fatal("malformed \\ new data");
            if (len<0) fatal("\\ new length less than 0");
            if ((q=find_addr(addr))>=0) {
                if (!(b[q].fl & BFL_ASSUMED)) {
                    debug("[!] line %d: new buffer %x:%d already exists as %x:%d.\n",cline,addr,len,b[q].addr,b[q].size);
                    problems++;
                }
                continue;
            }
            b[btop].iaddr=b[btop].addr=addr;
            b[btop].isize=b[btop].size=len;
            b[btop].st=ST_CUR;
            b[btop].t=bufno;
            if (T_verb) debug("+ New #%d: %x:%d\n",btop,addr,len);
            btop=-1;
            continue;
        }

        else if (!strncmp(x,"\\ discard: mem",14)) {

            // Check for presence. Remove buffer.
            // \ discard: mem %x

            if (sscanf(x,"\\ discard: mem %x:%d",&addr,&len)!=2) fatal("malformed \\ discard");
            if (len<0) fatal("\\ discard len less than 0");

            if ((q=find_inrange(addr,addr+len))<0) {
                debug("[!] line %d: discard of non-existing %x:%d\n",cline,addr,len);
                problems++;
                continue;
            }

            if (T_verb) debug("- Discard #%d: %x:%d (%x:%d)\n",q,addr,len,b[q].addr,b[q].size);

            b[q].addr=addr;
            b[q].size=len;
            b[q].st=ST_PAST;

            if (strstr(x,"[is within")) {
                q=find_addr(addr);
                if (q<=0) continue;
                b[q].st=ST_FREE;
            }

            btop=-1;

            continue;
        }

        else if (!strncmp(x,"\\ remap",7)) {
            unsigned int a1,a2;
            x+=9;
            if (sscanf(x,"%x:%d -> %x:%d",&a1,&a2,&addr,&len)!=4) fatal("malformed \\ merge");

            if ((q=find_inrange(a1,a1+a2))<0) {
                problems++;
                debug("[!] line %d: remap of non-existing a1 %x:%d\n",cline,a1,a2);
                q=btop;
                b[q].iaddr=addr; b[q].isize=len;
                b[q].t=bufno;
                btop=-1;
            }

            b[q].addr=addr;
            b[q].size=len;
            b[q].st=ST_CUR;

            if (T_verb) debug("= Merged into #%d: %x | %x = %x:%d\n",q,a1,a2,addr,len);

            continue;
        }

        else if (!strncmp(x,"\\ merge",7)) {
            unsigned int a1,a2,l1,l2,any=0;
            // Eliminate all buffers within this one. Create new.
            // \ merge [??]: bffff770:50 bffff740:64 (first seen in S main:fstat) -> bffff740:98
            x+=14;
            if (sscanf(x,"%x:%d %x:%d (%*[^)]) -> %x:%d",&a1,&l1,&a2,&l2,&addr,&len)<6) fatal("malformed \\ merge");
            while ((q=find_inrange(addr,addr+len))>=0) {
                if (T_verb) debug("- Discard: %x [#%d] in merge with %x:%d %x:%d\n",b[q].addr,q,a1,l1,a2,l2);
                b[q].st=ST_FREE;
                if (b[q].addr == a1) any++; else
                    if (b[q].addr == a2) any++;
            }

            b[btop].iaddr=b[btop].addr=addr;
            b[btop].isize=b[btop].size=len;
            b[btop].st=ST_CUR;
            b[btop].t=bufno;
            if (!any) debug("[!] line %d: merge of non-existing buffers [%x | %x -> %x]\n",cline,a1,a2,addr);
            if (T_verb) debug("= Merged into #%d: %x | %x = %x:%d\n",btop,a1,a2,addr,len);
            btop=-1;
            continue;
        }

        else if (!strncmp(x,"- remap: non-existing",21)) {
            if (!(x=strchr(x,'>'))) fatal("malformed - remap line");
            x+=1;
            if (sscanf(x," %x:%d",&addr,&len)<2) fatal("malformed \\ new data");
            if (len<0) fatal("- remap less than 0");
            b[btop].iaddr=b[btop].addr=addr;
            b[btop].isize=b[btop].size=len;
            b[btop].st=ST_CUR;
            b[btop].t=bufno;
            problems++;
            debug("[!] line %d: remap of non-existing buffer\n",cline);
            if (T_verb) debug("+ Strange new #%d: %x:%d \n",btop,addr,len);
            btop=-1;
            continue;
        }

        else if (!strncmp(x,"- ",2)) {
            problems++;
            debug("[!] line %d: %s\n",cline,x+2);
        }

        else if (!strncmp(x,"+ ",2)) {
            // Check for presence. Not found? Add.
            // + 40018000 = 40018000:4096 <off 0> (first seen in S main:read)

            if (sscanf(x,"+ fd %d: ",&q)==1) {
                if (topfd<q) topfd=q;
                continue;
            }

            if (sscanf(x,"+ %x = %x:%d <off %d>",&q,&addr,&len,&q)!=4) continue;
            if (len<0) fatal("assumed new length < 0");
            if ((q=find_inrange(addr,addr+len))>=0) {
                while (q>=0) {
                    if ((b[q].addr == addr) && (b[q].size == len)) goto getmeout;
                    if (T_verb) debug("= Adjust #%d into #%d: %x:%d -> %x:%d\n",q,btop,b[q].addr,b[q].size,addr,len);
                    b[q].st=ST_FREE;
                    q=find_inrange(addr,addr+len);
                }
            } else {
                if (T_verb) debug("+ Assumed new #%d: %x:%d\n",btop,addr,len);
            }
            b[btop].fl=BFL_ASSUMED;
            b[btop].iaddr=b[btop].addr=addr;
            b[btop].isize=b[btop].size=len;
            b[btop].st=ST_CUR;
            b[btop].t=bufno;
            btop=-1;
            continue;
        }

        else if (!strncmp(x,"@ ",2)) {
            char* w=strstr(x+2," fd ");
            int i;
            if ((!w) || (sscanf(w+4,"%d",&i)!=1)) fatal("malformed @ line.");
            if (topfd<i) topfd=i;
        }

getmeout:

    }

bailout:

    left=0; over=0;
    for (i=0;i<breally;i++) {
        if (b[i].st==ST_CUR) left++;
        if (b[i].st!=ST_FREE) { b[i].num=bnum++; over++; }

    }

    if (!exitcond) debug("[!] Warning: file truncated!\n");

    debug("[+] Found %d buffers (%d slots, %d static), %d problems.\n",over,bufno,left,problems);
    debug("[+] Highest fd found: %d\n",topfd);

    {
        struct bufdesc x[MAXADDR];
        bzero(x,sizeof(x));

        for (i=0;i<bufno;i++) {
            int j;
            if (!(i % 123)) debug("[+] Sorting buffers... %0.02f%% done\r",((float)i*100.0)/((float)bufno));
            for (j=0;j<breally;j++) {
                if ((b[j].t==i) && b[j].st) {
                    b[j].st=ST_CUR;
                    memcpy(&x[j],&b[j],sizeof(struct bufdesc));
                    bynum[b[j].num]=j;
                    break;
                }
            }
        }

        memcpy(b,x,sizeof(x));

    }

    debug("[+] Buffers successfully sorted using bogosort algorithm.\n");

    if (T_verb) {
        debug("[+] BUFFERS: ");
        for (i=0;i<breally;i++) debug("%d [%d] %x:%d ",i,b[i].num,b[i].addr,b[i].size);
        debug("\n");
    }

}

#define MOD_ACC     1
#define MOD_CLOSE   2
#define MOD_OPEN    3
#define MOD_DUP     4

#define B_READ  1
#define B_WRITE 2

int  nest;
char fname[MAXNEST][MAXNAME+1];
char a[MAXNEST][MAXADDR];
FILE* fnfile[MAXNEST];
int fnum;
char* modtable;

void parse_functions(void) {
    int i;
    time_t ti;
    char* x,*ox;
    char obuf[1024];
    char hadconditional=0;
    char bounceback=0;

    // gcc prior to 2.96 bug workaround.
    modtable=malloc(topfd+1);
    bzero(modtable,topfd+1);

    my_seek(0);
    cline=0;
    ti=time(0);

    debug("*** PHASE 2: Parsing functions, logging buffer activity...\n");

    strcpy(fname[0],"main");
    if (!(fnfile[0]=fopen(getname("F",0),"w"))) fatal("cannot open fnfile");

    // negative
    // Tuesday, December 18, 2001
    // <!--- header.txt --->
    outf("<!--- header.txt --->\n"
            "<html>\n"
            "<head>\n"
            "<title> fenris: %s, %s </title>\n"
            "<style type=\"text/css\">\n"
            "  A.ttip { text-decoration: none; color: none; }\n"
            "</style>\n"
            "</head>\n\n"
            "<!-- Automatically generated by 'ragnarok', a part of project Fenris -->\n"
            "<!--     Brought to you by Michal Zalewski (lcamtuf@coredump.cx)     -->\n"
            "<!--                http://lcamtuf.coredump.cx/fenris/               -->\n\n",progname,ctime(&ti));

    // Fixed header
    outf(header);

    // Lame script
    outf(ascript);

    outf("<table border=1><tr bgcolor=#efffff><td><font face=helvetica,arial>"
            "Program: <b>%s</td><tr bgcolor=#ffefff><td><font "
            "face=helvetica,arial>Date: <b>%s</td></table>\n\n",
            progname,ctime(&ti));
    // negative
    // Tuesday, December 18, 2001
    // <!--- index.txt --->
    outf("<!--- index.txt --->\n<p><a name=A1><font size=+0><b>Buffer / function interaction:</b></font><br>\n\n" NAVI);

    //  outf("<p><a name=A1><font size=+0><b>Buffer / function interaction:</b></font><br>\n\n" NAVI);

    outf(hinttable);

    outf("\n<table border=0>%s\n",NRO);

    outf("<b>line</b>" NFI "<b>function</b>" NFI "<b>buffers</b>" NFI "<b>descriptors</b>%s\n", NRO);

    outf(" " NFI ".- <b><a href=\"#f0\">main</a></b>" NFI "&nbsp;" NFI "&nbsp;%s\n",NRO);

    while ((x=my_gets())) {
        int pid;
        cline++;
        ox=x;

        debug("[+] Found %d function calls, %0.02f%% done...\r",fnum,((float)(my_ptr-my_file)) * 100.0 / ((float)(my_end-my_file)));

reanalyze:

        if (!strncmp(x,"+++ Process ",11) && strstr(x,"image replaced")) {
            sscanf(x+11,"%d",&pid);
            if (pid==forcepid) goto bailout_parse;
            continue;
        }

        { char *spa,*naw,*dwu;
            // Skip EIP!
            if ((spa=strchr(x,' ')))
                if ((naw=strchr(x,']')))
                    if ((dwu=strchr(x,':')))
                        if ((spa>naw) && (naw<dwu) && (spa<dwu)) x=spa+1;
        }

        if (sscanf(x,"%d:",&pid)!=1) continue;
        if (pid!=forcepid) continue;
        x=strchr(x,' ');
        while (*x==' ') x++;
        if (!strncmp(x,"[L] ",4)) x+=4;

        if (!strncmp(x,"...return",9) || !strncmp(x,"...left",7) || !strncmp(x,"...function",11)) {

            char ttip[1000];
            strcpy(ttip,x);
            { int i;for (i=0;i<strlen(ttip);i++) {
                                                     if (ttip[i]=='<') ttip[i]='('; else
                                                         if (ttip[i]=='>') ttip[i]=')'; else
                                                             if (ttip[i]=='"') ttip[i]='`'; else
                                                                 if (ttip[i]=='\'') ttip[i]='`';
                                                 }
            }

            if (nest-1>=0) fprintf(fnfile[nest-1],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
            fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <b>%s</b>\n",cline,cline,ox);

            ox=x=my_gets();
            cline++;

reprocess:

            if (!x) break; // Doh.
            x=strchr(x,' ');
            if (!x) break; // Doh^2.

            { char *spa,*naw,*dwu;
                // Skip EIP!
                if ((spa=strchr(x,' ')))
                    if ((naw=strchr(x,']')))
                        if ((dwu=strchr(x,':')))
                            if ((spa>naw) && (naw<dwu) && (spa<dwu)) x=spa+1;
            }

            while (*x==' ') x++;
            if (!strncmp(x,"[L] ",4)) x+=4;

            if (!strncmp(x,"// function has",15)) {
                ox=x=my_gets();
                cline++;
                fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                goto reprocess;
            }

            // Add other objects! Buffer is not enough
            else if (!strncmp(x,"* READ buffer",13)) {
                int add,f;
                if (sscanf(x,"* READ buffer %x",&add)!=1) fatal("malformed read");
                f=find_addr(add);
                if (f<0) debug("[!] line %d: READ on non-existing buffer %x.\n",cline,add);
                else {
                    a[nest][b[f].num] |= B_READ;
                    { FILE* qq;
                        qq=fopen(getname("B",b[f].num),"a");
                        if (!qq) fatal("fopen");
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                        // fprintf(qq,"%s:\n%s\n",fname[nest],x);
                        fclose(qq);
                    }
                }

                // Skip +es
                x=ox=my_gets();
                fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                cline++;
                if (!strstr(ox," + ")) debug("[!] line %d: no '+'\n",cline);

                // Get next line, whatever it is.
                x=ox=my_gets();
                cline++;

                // Skip last input if necessary.
                if (strstr(ox,"last input")) {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    x=ox=my_gets();
                    cline++;
                }

                goto reprocess;
            }

            // Add other objects! Buffer is not enough
            else if (!strncmp(x,"* READ local",11)) {
                int add,f;
                if (sscanf(x,"* READ local object %*s (%x)",&add)<1) fatal("malformed read");
                f=find_addr(add);
                if (f<0) debug("[!] line %d: READ on non-existing buffer %x.\n",cline,add);
                else {
                    a[nest][b[f].num] |= B_READ;
                    { FILE* qq;
                        qq=fopen(getname("B",b[f].num),"a");
                        if (!qq) fatal("fopen");
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                        // fprintf(qq,"%s:\n%s\n",fname[nest],x);
                        fclose(qq);
                    }
                }

                // Skip +es
                x=ox=my_gets();
                fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                cline++;
                if (!strstr(ox," + ")) debug("[!] line %d: no '+'\n",cline);

                // Get next line, whatever it is.
                x=ox=my_gets();
                cline++;

                // Skip last input if necessary.
                if (strstr(ox,"last input")) {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    x=ox=my_gets();
                    cline++;
                }

                goto reprocess;
            }

            // Add other objects! Buffer is not enough
            else if (!strncmp(x,"* READ share",11)) {
                int add,f;
                if (sscanf(x,"* READ shared object %*s (%x)",&add)<1) fatal("malformed read");
                f=find_addr(add);
                if (f<0) debug("[!] line %d: READ on non-existing buffer %x.\n",cline,add);
                else {
                    a[nest][b[f].num] |= B_READ;
                    { FILE* qq;
                        qq=fopen(getname("B",b[f].num),"a");
                        if (!qq) fatal("fopen");
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                        // fprintf(qq,"%s:\n%s\n",fname[nest],x);
                        fclose(qq);
                    }
                }

                // Skip +es
                x=ox=my_gets();
                fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                cline++;
                if (!strstr(ox," + ")) debug("[!] line %d: no '+'\n",cline);

                // Get next line, whatever it is.
                x=ox=my_gets();
                cline++;

                // Skip last input if necessary.
                if (strstr(ox,"last input")) {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    x=ox=my_gets();
                    cline++;
                }

                goto reprocess;
            }

            else if (!strncmp(x,"* WRITE buffer",14)) {
                int add,f;
                if (sscanf(x,"* WRITE buffer %x",&add)!=1) fatal("malformed write");
                f=find_addr(add);
                if (f<0) debug("[!] line %d: WRITE on non-existing buffer %x.\n",cline,add);
                else {
                    a[nest][b[f].num] |= B_WRITE;
                    { FILE* qq;
                        qq=fopen(getname("B",b[f].num),"a");
                        if (!qq) fatal("fopen");
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                        //            fprintf(qq,"%s:\n%s\n",fname[nest],x);
                        fclose(qq);
                    }
                }

                // Skip +es
                ox=my_gets();
                fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                cline++;

                if (!strstr(ox," + ")) debug("[!] line %d: no '+'\n",cline);

                // Get next line.
                x=ox=my_gets();
                cline++;

                // Check for last input.
                if (strstr(ox,"last input")) {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    x=ox=my_gets();
                    cline++;
                }

                goto reprocess;
            }

            else if (!strncmp(x,"* WRITE local ",14)) {
                int add,f;
                if (sscanf(x,"* WRITE local object %*s (%x)",&add)<1) fatal("malformed write");
                f=find_addr(add);
                if (f<0) debug("[!] line %d: WRITE on non-existing buffer %x.\n",cline,add);
                else {
                    a[nest][b[f].num] |= B_WRITE;
                    { FILE* qq;
                        qq=fopen(getname("B",b[f].num),"a");
                        if (!qq) fatal("fopen");
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                        //            fprintf(qq,"%s:\n%s\n",fname[nest],x);
                        fclose(qq);
                    }
                }

                // Skip +es
                ox=my_gets();
                fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                cline++;

                if (!strstr(ox," + ")) debug("[!] line %d: no '+'\n",cline);

                // Get next line.
                x=ox=my_gets();
                cline++;

                // Check for last input.
                if (strstr(ox,"last input")) {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    x=ox=my_gets();
                    cline++;
                }

                goto reprocess;
            }

            else if (!strncmp(x,"* WRITE shared",14)) {
                int add,f;
                if (sscanf(x,"* WRITE shared object %*s (%x)",&add)<1) fatal("malformed write");
                f=find_addr(add);
                if (f<0) debug("[!] line %d: WRITE on non-existing buffer %x.\n",cline,add);
                else {
                    a[nest][b[f].num] |= B_WRITE;
                    { FILE* qq;
                        qq=fopen(getname("B",b[f].num),"a");
                        if (!qq) fatal("fopen");
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                        fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                        //            fprintf(qq,"%s:\n%s\n",fname[nest],x);
                        fclose(qq);
                    }
                }

                // Skip +es
                ox=my_gets();
                fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                cline++;

                if (!strstr(ox," + ")) debug("[!] line %d: no '+'\n",cline);

                // Get next line.
                x=ox=my_gets();
                cline++;

                // Check for last input.
                if (strstr(ox,"last input")) {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    x=ox=my_gets();
                    cline++;
                }

                goto reprocess;
            }

            fclose(fnfile[nest]);

            outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
            for (i=0;i<nest;i++) outf("|&nbsp;");
            outf("`-&nbsp;"
                    "<a class=ttip href=\"#\" onMouseover=\"showtip(this,event,'%s')\" onMouseout=\"hidetip()\">"
                    "%s</a>" NFI,ttip,fname[nest]);

            for (i=0;i<bnum;i++) {

                if (a[nest][i]) b[findbynum(i)].yet=1;

                if (b[findbynum(i)].st == ST_PAST) {
                    if (a[nest][i]) outf("<a href=\"#b%d\">*</a>",i); else outf(".");
                } else

                    if (!b[findbynum(i)].yet) {
                        if (a[nest][i]) outf("<a href=\"#b%d\">*</a>",i); else outf(".");
                    } else

                        switch (a[nest][i]) {
                            case 0:              outf(":"); break;
                            case B_READ:         outf("<a href=\"#b%d\">r</a>",i); break;
                            case B_WRITE:        outf("<a href=\"#b%d\">W</a>",i); break;
                            case B_WRITE|B_READ: outf("<a href=\"#b%d\">X</a>",i); break;
                            default:             outf("?");
                        }
            }

            outf(NFI "&nbsp;%s\n",NRO);

            nest--;

            if (nest<0) break;

            x=ox;
            goto reanalyze;

        }

        fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
        strcpy(obuf,ox);

        if (*x!='<') hadconditional=0;

        // Parse all other stuff.

        if (!strncmp(x,"\\ discard",9)) {
            unsigned int addr;
            int len,q;
            if (sscanf(x,"\\ discard: mem %x:%d",&addr,&len)!=2) continue;
            if ((q=find_addr(addr))<0) continue;
            b[q].st=ST_PAST;
            continue;
        }

        else if (!strncmp(x,"\\ merge",7)) {
            unsigned int addr,q;
            x+=14;
            if (sscanf(x,"%x:%d %x:%d (%*[^)]) -> %x:%d",&q,&q,&q,&q,&addr,&q)<6) continue;
            if ((q=find_addr(addr))>=0) {
                a[nest][b[q].num] |= B_READ;
                { FILE* qq;
                    qq=fopen(getname("B",b[q].num),"a");
                    if (!qq) fatal("fopen");
                    fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                    fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                    //            fprintf(qq,"%s:\n%s\n",fname[nest],ox);
                    fclose(qq);
                }
            }
            else debug("[!] line %d: \\ merge on unknown %x.\n",cline,addr);
            continue;
        }

        else if (!strncmp(x,"\\ remap ",8)) {
            unsigned int a1,a2;
            unsigned int addr;
            int len,q;
            x+=9;
            if (sscanf(x,"%x:%d -> %x:%d",&a1,&a2,&addr,&len)!=4) continue;
            if ((q=find_addr(a1))<0) continue;
            b[q].addr=addr;
            b[q].size=len;
            continue;
        }

        else if (!strncmp(x,"\\ new",5)) {
            unsigned int addr;
            int len,q;
            if (!strstr(x,"buffer candidate:")) continue;
            x=strchr(x,':')+1;
            sscanf(x," %x:%d",&addr,&len);
            if ((q=find_addr(addr))>=0) {
                a[nest][b[q].num] |= B_READ;
                { FILE* qq;
                    qq=fopen(getname("B",b[q].num),"a");
                    if (!qq) fatal("fopen");
                    fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                    fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                    //            fprintf(qq,"%s:\n%s\n",fname[nest],ox);
                    fclose(qq);
                }
            }
            else debug("[!] line %d: \\ new on unknown %x.\n",cline,addr);
            continue;
        }

        else if (!strncmp(x,"+ ",2)) {
            unsigned int addr;
            int len,q;
            if (sscanf(x,"+ %x = %x:%d <off %d>",&q,&addr,&len,&q)!=4) continue;
            if ((q=find_addr(addr))>=0) {
                a[nest][b[q].num] |= B_READ;
                { FILE* qq;
                    qq=fopen(getname("B",b[q].num),"a");
                    if (!qq) fatal("fopen");
                    //            fprintf(qq,"%s:\n%s\n",fname[nest],ox);
                    fprintf(qq,"<a href=\"#l%d\">%07d</a>  in %s:<br>\n",cline,cline,fname[nest]);
                    fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                    fclose(qq);
                }
            }
            else debug("[!] line %d: + on unknown %x.\n",cline,addr);
            continue;
        }

        else if (!strncmp(x,"# Matches for",13)) {
            x=strchr(x,':')+2;
            outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
            for (i=0;i<nest;i++) outf("|&nbsp;");
            outf("<font color=red>|-&gt;&nbsp;%s " NFI "&nbsp;" NFI "&nbsp;%s\n",x+2,NRO);
            continue;
        }

        else if (!strncmp(x,"\\ buffer ",9)) {
            int q;
            unsigned int addr;
            if (sscanf(x,"\\ buffer %x modified",&addr)!=1) continue;
            if ((q=find_addr(addr))>=0) a[nest][b[q].num] |= B_WRITE;
            else debug("[!] line %d: modified on unknown %x.\n",cline,addr);
            continue;
        }

        // Mom, tell me about structural programming! Well, this used to
        // be standalone, then I decided to reference it later, then it
        // became obsolete at this location, but I'm way too lazy to
        // move it to a separate function ;P
        else if (!strncmp(x,"\\ data migration",16)) {
            unsigned int a1,a2;
            int q1,q2;
handle_migration:
            if (sscanf(x,"\\ data migration: %x to %x",&a1,&a2)!=2)
                fatal("malformed \\ data migration");
            if ((q1=find_addr(a1))<0)
                debug("[!] line %d: data migration source unknown (%x).\n",cline,a1);
            if ((q2=find_addr(a2))<0)
                debug("[!] line %d: data migration destination unknown (%x).\n",cline,a2);
            if (q1==q2) {
                for (a1=0;a1<q1;a1++) outf("&nbsp;");
                outf("<a href=\"#b%d\">X</a>%s\n",q1,NRO);
            } else if (q1 < q2) {
                for (a1=0;a1<q1;a1++) outf("&nbsp;");
                outf("<a href=\"#b%d\">S</a>",q1);
                for (a1=0;a1<q2-q1-1;a1++) outf("-");
                outf("<a href=\"#b%d\">D</a>" NFI "&nbsp;%s\n",q2,NRO);
            } else {
                for (a1=0;a1<q2;a1++) outf("&nbsp;");
                outf("<a href=\"#b%d\">D</a>",q2);
                for (a1=0;a1<q1-q2-1;a1++) outf("-");
                outf("<a href=\"#b%d\">S</a>" NFI "&nbsp;%s\n",q1,NRO);
            }
            if (bounceback==1) { bounceback=0; goto knowncont; } else
                if (bounceback==2) { bounceback=0; goto sysccont; } else
                    fatal("standalone data migration?!");

            continue;
        }

        else if (!strncmp(x,"U ",2)) {
            char ttip[1000];
            strcpy(ttip,x+2);
            { int i;for (i=0;i<strlen(ttip);i++) {
                                                     if (ttip[i]=='<') ttip[i]='('; else
                                                         if (ttip[i]=='>') ttip[i]=')'; else
                                                             if (ttip[i]=='"') ttip[i]='`'; else
                                                                 if (ttip[i]=='\'') ttip[i]='`';
                                                 }
            }
            fnum++;
            *(x-1)=0;
            fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  %s <font color=blue>==&gt; Click <a href=\"#f%d\">here</a> for trace of this libcall &lt;==</font>\n",cline,cline,ox,fnum);
            nest++;
            if (nest>=MAXNEST) fatal("MAXNEST exceeded");
            fnfile[nest]=fopen(getname("F",fnum),"w");
            if (!fnfile[nest]) fatal("cannot open fnfile");
            fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <b>%s</b>\n",cline,cline,obuf);
            *strchr(x+2,' ')=0;
            outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);

            for (i=0;i<nest;i++) outf("|&nbsp;");
            outf(".-&nbsp;<a href=\"#f%d\""
                    " onMouseover=\"showtip(this,event,'%s')\""
                    " onMouseout=\"hidetip()\""
                    "><font color=green>%s</a>" NFI "&nbsp;" NFI "&nbsp;%s\n",fnum, ttip, x+2,
                    NRO);
            strncpy(fname[nest],x+2,MAXNAME);
            bzero(a[nest],MAXADDR);
            continue;

        }

        else if (!strncmp(x,"local ",6)) {
            char ttip[1000];
            strcpy(ttip,x+6);
            { int i;for (i=0;i<strlen(ttip);i++) {
                                                     if (ttip[i]=='<') ttip[i]='('; else
                                                         if (ttip[i]=='>') ttip[i]=')'; else
                                                             if (ttip[i]=='"') ttip[i]='`'; else
                                                                 if (ttip[i]=='\'') ttip[i]='`';
                                                 }
            }
            fnum++;
            *(x-1)=0;
            fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  %s <font color=blue>==&gt; Click <a href=\"#f%d\">here</a> for trace of this function &lt;==</font>\n",cline,cline,ox,fnum);
            nest++;
            if (nest>=MAXNEST) fatal("MAXNEST exceeded");
            fnfile[nest]=fopen(getname("F",fnum),"w");
            if (!fnfile[nest]) fatal("cannot open fnfile");
            fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <b>%s</b>\n",cline,cline,obuf);
            *strchr(x+6,' ')=0; // Doh.
            outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
            for (i=0;i<nest;i++) outf("|&nbsp;");
            outf(".-&nbsp;<a href=\"#f%d\""
                    " onMouseover=\"showtip(this,event,'%s')\" onMouseout=\"hidetip()\""
                    "><b>%s</b></a>" NFI "&nbsp;" NFI "&nbsp;%s\n",fnum,ttip,x+6,NRO);
            strncpy(fname[nest],x+6,MAXNAME);
            bzero(a[nest],MAXADDR);
            continue;
        }

        else if (!strncmp(x,"L ",2)) {
            unsigned int addr;
            int len,q,i;
            char mem[MAXADDR];
            char tmp[1024];
            int migrated=0;
            char ttip[1000];
            strcpy(ttip,x+2);
            { int i;for (i=0;i<strlen(ttip);i++) {
                                                     if (ttip[i]=='<') ttip[i]='('; else
                                                         if (ttip[i]=='>') ttip[i]=')'; else
                                                             if (ttip[i]=='"') ttip[i]='`'; else
                                                                 if (ttip[i]=='\'') ttip[i]='`';
                                                 }
            }
            bzero(modtable,sizeof(modtable));

            migrated=0;
            strcpy(tmp,x);
            bzero(mem,sizeof(mem));

            while ((ox=x=my_gets())) {
                cline++;

                { char *spa,*naw,*dwu;
                    // Skip EIP!
                    if ((spa=strchr(x,' ')))
                        if ((naw=strchr(x,']')))
                            if ((dwu=strchr(x,':')))
                                if ((spa>naw) && (naw<dwu) && (spa<dwu)) x=spa+1;
                }

                x=strchr(x,' ');
                if (!x) continue;
                while (*x==' ') x++;
                if (!strncmp("last input",x,10)) continue;

                if (x[0]=='+') {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    if (sscanf(x,"+ fd %d: ",&q)==1) {
                        FILE* f;
                        if (!modtable[q]) modtable[q]=MOD_ACC;
                        f=fopen(getname("D",q),"a");
                        if (!f) pfatal("fopen");
                        fprintf(f,"<b><a href=\"#l%d\">%07d</a></b>  %s<br>\n",cline,cline,tmp);
                        fprintf(f,"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i><p>\n",cline,cline,x);
                        fclose(f);
                        continue;
                    }
                    if (sscanf(x,"+ %x = %x:%d <off %d>",&q,&addr,&len,&q)!=4) continue;
                    if ((q=find_addr(addr))>=0) {
                        mem[b[q].num] |= B_READ;
                        { FILE* qq;
                            qq=fopen(getname("B",b[q].num),"a");
                            if (!qq) fatal("fopen");
                            fprintf(qq,"<a href=\"#l%d\">%07d</a>  %s<br>\n",cline,cline,tmp);
                            fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                            //            fprintf(qq,"%s:\n%s\n",tmp,x);
                            fclose(qq);
                        }

                    }
                    else debug("[!] line %d: + on unknown %x.\n",cline,addr);
                    continue;
                } else if (x[0]=='\\') {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    if (strstr(x,"buffer candidate:")) {
                        x=strchr(x,':')+1;
                        sscanf(x," %x:%d",&addr,&len);
                        if ((q=find_addr(addr))>=0) {
                            mem[b[q].num] |= B_READ;
                            { FILE* qq;
                                qq=fopen(getname("B",b[q].num),"a");
                                if (!qq) fatal("fopen");
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  %s<br>\n",cline,cline,tmp);
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                                //            fprintf(qq,"%s:\n%s\n",tmp,ox);
                                fclose(qq);
                            }
                        }
                        else debug("[!] line %d: \\ new on unknown %x.\n",cline,addr);
                        continue;
                    } else if (strstr(x,"\\ data migration")) {
                        sscanf(x,"\\ data migration: %x to %x",&q,&addr);
                        if ((q=find_addr(addr))>=0) mem[b[q].num] |= B_WRITE;

                        *strchr(tmp+2,' ')=0; // Doh.
                        outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
                        for (i=0;i<nest+1;i++) outf("|&nbsp;");
                        outf(""
                                "<a class=ttip href=\"#\" onMouseover=\"showtip(this,event,'%s')\" onMouseout=\"hidetip()\">"
                                "<font color=blue>%s</a>" NFI,ttip,tmp+2);
                        migrated=1;

                        bounceback=1; goto handle_migration;
knowncont:
                    } else if (strstr(x,"\\ merge")) {
                        x+=14;
                        if (sscanf(x,"%x:%d %x:%d (%*[^)]) -> %x:%d",&q,&q,&q,&q,&addr,&len)<6) continue;
                        if ((q=find_addr(addr))>=0) {
                            mem[b[q].num] |= B_READ;
                            { FILE* qq;
                                qq=fopen(getname("B",b[q].num),"a");
                                if (!qq) fatal("fopen");
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  %s<br>\n",cline,cline,tmp);
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                                //            fprintf(qq,"%s:\n%s\n",tmp,ox);
                                fclose(qq);
                            }
                        }
                        else debug("[!] line %d: \\ merge on unknown %x.\n",cline,addr);
                        continue;
                    } else if (strstr(x,"\\ discard: mem")) {
                        x+=15;
                        if (sscanf(x,"%x:%d",&addr,&len)<2) continue;
                        if ((q=find_addr(addr))>=0) b[q].st=ST_PAST;
                        else debug("[!] line %d: \\ L discard on unknown %x.\n",cline,addr);

                        continue;
                    } else if (strstr(x,"\\ buffer")) {
                        x+=8;
                        if (!strstr(x,"modified")) continue;
                        if (sscanf(x,"%x",&addr)<1) continue;
                        if ((q=find_addr(addr))>=0) mem[b[q].num] = B_WRITE;
                        else debug("[!] line %d: \\ modified unknown %x.\n",cline,addr);
                        continue;
                    }
                } else break;
            }

            if (migrated) { x=ox; goto reanalyze; }

            *strchr(tmp+2,' ')=0; // Doh.

            outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
            for (i=0;i<nest+1;i++) outf("|&nbsp;");

            outf("<a class=ttip href=\"#\" onMouseover=\"showtip(this,event,'%s')\" onMouseout=\"hidetip()\">"
                    "<font color=blue>%s</a>" NFI,ttip,tmp+2);

            for (i=0;i<bnum;i++) {
                if (mem[i]) b[findbynum(i)].yet=1;

                if (b[findbynum(i)].st == ST_PAST) {
                    if (mem[i]) outf("<a href=\"#b%d\">*</a>",i); else outf(".");
                } else

                    if (!b[findbynum(i)].yet) {
                        if (mem[i]) outf("<a href=\"#b%d\">*</a>",i); else outf(".");
                    } else

                        switch (mem[i]) {
                            case 0:              outf(":"); break;
                            case B_READ:         outf("<a href=\"#b%d\">r</a>",i); break;
                            case B_WRITE:        outf("<a href=\"#b%d\">W</a>",i); break;
                            case B_WRITE|B_READ: outf("<a href=\"#b%d\">X</a>",i); break;
                            default:             outf("?");
                        }
            }

            outf(NFI);

            for (i=0;i<=topfd;i++) {
                switch (modtable[i]) {
                    case 0:              outf("."); break;
                    case MOD_ACC:        outf("<a href=\"#d%d\">+</a>",i); break;
                    case MOD_CLOSE:      outf("<a href=\"#d%d\">*</a>",i); break;
                    case MOD_DUP:        outf("<a href=\"#d%d\">#</a>",i); break;
                    case MOD_OPEN:       outf("<a href=\"#d%d\">O</a>",i); break;
                    default:             outf("?");
                }
            }

            outf("%s\n", NRO);

            x=ox;
            goto reanalyze;
        }

        else if (!strncmp(x,"SYS",3)) {
            unsigned int addr;
            int len,q,i;
            char mem[MAXADDR];
            char tmp[1024];
            int migrated=0;
            char ttip[1000];
            bzero(modtable,sizeof(modtable));

            strcpy(ttip,x);
            { int i;for (i=0;i<strlen(ttip);i++) {
                                                     if (ttip[i]=='<') ttip[i]='('; else
                                                         if (ttip[i]=='>') ttip[i]=')'; else
                                                             if (ttip[i]=='"') ttip[i]='`'; else
                                                                 if (ttip[i]=='\'') ttip[i]='`';
                                                 }
            }

            strcpy(tmp,x);
            bzero(mem,sizeof(mem));

            while ((ox=x=my_gets())) {
                cline++;

                { char *spa,*naw,*dwu;
                    // Skip EIP!
                    if ((spa=strchr(x,' ')))
                        if ((naw=strchr(x,']')))
                            if ((dwu=strchr(x,':')))
                                if ((spa>naw) && (naw<dwu) && (spa<dwu)) x=spa+1;
                }

                x=strchr(x,' ');
                if (!x) continue;
                while (*x==' ') x++;
                if (!strncmp("last input",x,10)) continue;

                if (x[0]=='+') {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    if (sscanf(x,"+ fd %d: ",&q)==1) {
                        FILE* f;
                        if (!modtable[q]) modtable[q]=MOD_ACC;
                        f=fopen(getname("D",q),"a");
                        if (!f) pfatal("fopen");
                        fprintf(f,"<b><a href=\"#l%d\">%07d</a></b>  %s<br>\n",cline,cline,tmp);
                        fprintf(f,"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i><p>\n",cline,cline,x);
                        fclose(f);
                        continue;
                    }
                    if (sscanf(x,"+ %x = %x:%d <off %d>",&q,&addr,&len,&q)!=4) continue;
                    if ((q=find_addr(addr))>=0) {
                        mem[b[q].num] |= B_READ;
                        { FILE* qq;
                            qq=fopen(getname("B",b[q].num),"a");
                            if (!qq) fatal("fopen");
                            fprintf(qq,"<a href=\"#l%d\">%07d</a>  %s<br>\n",cline,cline,tmp);
                            fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                            //            fprintf(qq,"%s:\n%s\n",tmp,ox);
                            fclose(qq);
                        }
                    }
                    else debug("[!] line %d: + on unknown %x.\n",cline,addr);
                    continue;
                } else if (x[0]=='\\') {
                    fprintf(fnfile[nest],"<b><a href=\"#l%d\">%07d</a></b>  <i>%s</i>\n",cline,cline,ox);
                    if (strstr(x,"buffer candidate:")) {
                        x=strchr(x,':')+1;
                        sscanf(x," %x:%d",&addr,&len);
                        if ((q=find_addr(addr))>=0) {
                            mem[b[q].num] |= B_READ;
                            { FILE* qq;
                                qq=fopen(getname("B",b[q].num),"a");
                                if (!qq) fatal("fopen");
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  %s<br>\n",cline,cline,tmp);
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                                //            fprintf(qq,"%s:\n%s\n",tmp,ox);
                                fclose(qq);
                            }
                        }
                        else debug("[!] line %d: \\ new on unknown %x.\n",cline,addr);
                        continue;
                    } else if (strstr(x,"\\ data migration")) {
                        sscanf(x,"\\ data migration: %x to %x",&q,&addr);
                        if ((q=find_addr(addr))>=0) mem[b[q].num] |= B_WRITE;

                        *strchr(strchr(tmp+3,' ')+1,' ')=0;
                        outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
                        for (i=0;i<nest+1;i++) outf("|&nbsp;");
                        outf("<a class=ttip href=\"#\" onMouseover=\"showtip(this,event,'%s')\" onMouseout=\"hidetip()\">"
                                "<font color=magenta>%s</a>" NFI,ttip,strchr(tmp+3,' ')+1);
                        migrated=1;

                        bounceback=2; goto handle_migration;
sysccont:
                    } else if (strstr(x,"\\ merge")) {
                        x+=14;
                        if (sscanf(x,"%x:%d %x:%d (%*[^)]) -> %x:%d",&q,&q,&q,&q,&addr,&len)<6) continue;
                        if ((q=find_addr(addr))>=0) {
                            mem[b[q].num] |= B_READ;
                            { FILE* qq;
                                qq=fopen(getname("B",b[q].num),"a");
                                if (!qq) fatal("fopen");
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  %s<br>\n",cline,cline,tmp);
                                fprintf(qq,"<a href=\"#l%d\">%07d</a>  <i>%s</i><p>\n",cline,cline,ox);
                                fclose(qq);
                            }
                        }
                        else debug("[!] line %d: \\ merge on unknown %x.\n",cline,addr);
                        continue;
                    } else if (strstr(x,"\\ buffer")) {
                        x+=8;
                        if (!strstr(x,"modified")) continue;
                        if (sscanf(x,"%x",&addr)<1) continue;
                        if ((q=find_addr(addr))>=0) mem[b[q].num] = B_WRITE;
                        else debug("[!] line %d: \\ modified unknown %x.\n",cline,addr);
                        continue;
                    }

                } else if (!strncmp(x,"@ ",2)) {
                    FILE* f;
                    char* w=strstr(x+2," fd ");
                    int i;
                    if ((!w) || (sscanf(w+4,"%d",&i)!=1)) fatal("malformed @ line.");
                    if (strstr(x,"duplicate")) modtable[i]=MOD_DUP; else
                        if (strstr(x,"created")) modtable[i]=MOD_OPEN; else
                            if (strstr(x,"removed")) modtable[i]=MOD_CLOSE; else
                                fatal("unrecognized @ line");
                    f=fopen(getname("D",i),"a");
                    if (!f) pfatal("fopen");
                    fprintf(f,"<b><a href=\"#l%d\">%07d</a></b>  %s<br>\n",cline,cline,tmp);
                    fprintf(f,"<b><a href=\"#l%d\">%07d</a></b>  <b>%s</b><p>\n",cline,cline,x);
                    fclose(f);
                } else break;
            }

            if (migrated) { x=ox; goto reanalyze; }

            *strchr(strchr(tmp+3,' ')+1,' ')=0;

            outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
            for (i=0;i<nest+1;i++) outf("|&nbsp;");

            outf("<a class=ttip href=\"#\" onMouseover=\"showtip(this,event,'%s')\" onMouseout=\"hidetip()\">"
                    "<font color=magenta>%s</a>" NFI,ttip,strchr(tmp+3,' ')+1);

            for (i=0;i<bnum;i++) {
                if (mem[i]) b[findbynum(i)].yet=1;

                if (b[findbynum(i)].st == ST_PAST) {
                    if (mem[i]) outf("<a href=\"#b%d\">*</a>",i); else outf(".");
                } else

                    if (!b[findbynum(i)].yet) {
                        if (mem[i]) outf("<a href=\"#b%d\">*</a>",i); else outf(".");
                    } else

                        switch (mem[i]) {
                            case 0:              outf(":"); break;
                            case B_READ:         outf("<a href=\"#b%d\">r</a>",i); break;
                            case B_WRITE:        outf("<a href=\"#b%d\">W</a>",i); break;
                            case B_WRITE|B_READ: outf("<a href=\"#b%d\">X</a>",i); break;
                            default:             outf("?");
                        }
            }

            outf(NFI);

            for (i=0;i<=topfd;i++) {
                switch (modtable[i]) {
                    case 0:              outf("."); break;
                    case MOD_ACC:        outf("<a href=\"#d%d\">+</a>",i); break;
                    case MOD_CLOSE:      outf("<a href=\"#d%d\">*</a>",i); break;
                    case MOD_DUP:        outf("<a href=\"#d%d\">#</a>",i); break;
                    case MOD_OPEN:       outf("<a href=\"#d%d\">O</a>",i); break;
                    default:             outf("?");
                }
            }

            outf("%s\n",NRO);

            x=ox;
            goto reanalyze;
        }

        else if (*x=='<') {
            // This is a conditional expression.
            if (hadconditional==1) continue;
            hadconditional=1;
            outf("<a href=\"#l%d\"><font size=-2>%d" NFI,cline,cline);
            for (i=0;i<nest+1;i++) outf("|&nbsp;");
            outf("<font color=red>(conditional)" NFI "<font color=red>%s " NFI "&nbsp;%s\n",strchr(x,':')+2,NRO);
            continue;
        }

        // Hell knows what.

    }

bailout_parse:

    debug("[+] Found %d function calls, done.                     \n",fnum);

    if (nest>=0) outf("&nbsp;" NFI "[truncated?] " NFI "&nbsp;");
    outf("</td></table>\n\n");

}

char* g_fn[MAXFNCT];
FILE* g_fd[MAXFNCT];
int g_top;

void glue_together(void) {
    int i;
    char buf[1000];
    char* x;
    debug("*** PHASE 3: Generating final report.\n");

    debug("[+] Migrating function dumps to main file...\n");
    // negative
    // Tuesday, December 18, 2001
    // <!--- calls.txt --->
    outf("<!--- calls.txt --->\n<br>&nbsp;<p><hr><br><a name=A2><font size=+0><b>Function invocations:</b></font><br>\n\n" NAVI);
    outf("<pre><font face=\"lucida,courier,monospaced,fixed\">");

    outf("<b>%07d</b>  <b>main (...)</b>\n",0);

    for (i=0;i<=fnum;i++) {
        int first=1;
        FILE* f;
        f=fopen(getname("F",i),"r");
        if (!f) pfatal("fopen");
        outf("<a name=\"f%d\">",i);
        while (fgets(buf,sizeof(buf),f)) {
            outf("%s",buf);
            if (first) {
                int i;
                char *x,*y;
                char tcopy[1000];
                char b[1000];

                first=0;

                strcpy(tcopy,buf);
                if ((x=strstr(tcopy," U "))) x+=3; else {
                    x=strstr(tcopy," local ");
                    if (x) x+=7; else continue;
                }

                y=strchr(x,' ');
                *y=0;
                for (i=0;i<g_top;i++) if (!strcmp(x,g_fn[i])) break;
                if (i>=MAXFNCT) fatal("MAXFNCT exceeded");
                sprintf(b,"%s:S:%s",ofip,x);
                if (!g_fn[i]) {
                    g_top++;
                    g_fn[i]=strdup(x);
                    g_fd[i]=fopen(b,"w+");
                    if (!g_fd[i]) pfatal("fopen");
                    outf("<font color=blue><b>    [ Click <a href=\"#S%s\">here</a> for calls summary ]</b></font>\n",x);
                }
                fprintf(g_fd[i],"%s",buf);
            }
        }
        outf("\n");
        fclose(f);
        unlink(getname("F",i));
    }

    outf("</font></pre>\n</pre>\n");

    debug("[+] Generating function call summary info...\n");
    // negative
    // Tuesday, December 18, 2001
    // <!--- params.txt --->
    outf("<!--- params.txt --->\n<br>&nbsp;<p><hr><br><font size=+0><a name=A3><b>Function call summary:</b></font><br>\n\n" NAVI);
    outf("<pre><font face=\"lucida,courier,monospaced,fixed size=-2\">");

    for (i=0;i<g_top;i++) {
        fseek(g_fd[i],0,0);
        outf("\n<a name=\"S%s\"><font color=green>Function %s</font>:\n",g_fn[i],g_fn[i]);
        while (fgets(buf,sizeof(buf),g_fd[i])) {
            outf("%s",buf);
        }
        sprintf(buf,"%s:S:%s",ofip,g_fn[i]);
        unlink(buf);
        fclose(g_fd[i]);
    }

    if (g_top<=0) outf("[no function calls]\n");

    outf("</font></pre>\n\n");

    debug("[+] Migrating buffer history...\n");
    // negative
    // Tuesday, December 18, 2001
    // <!--- buffers.txt --->
    outf("<!--- buffers.txt --->\n<br>&nbsp;<p><hr><br><font size=+0><a name=A4><b>Buffer history:</b></font><br>\n\n" NAVI);

    for (i=0;i<bufno;i++) {
        char* name=getname("B",i);
        if (!access(name,F_OK)) {
            FILE* f;
            f=fopen(name,"r");
            if (!f) pfatal("fopen");
            outf("<p>\n<a name=\"b%d\"><font color=green>Buffer %d</font>:<p>\n",i,i);
            while (fgets(buf,sizeof(buf),f)) {
                outf("%s",buf);
            }
            unlink(name); fclose(f);
        }
    }

    debug("[+] Generating file descriptor history...\n");
    // negative
    // Tuesday, December 18, 2001
    // <!--- io.txt --->
    outf("<!--- io.txt --->\n<br>&nbsp;<p><hr><br><font size=+0><a name=A6><b>File descriptor history:</b></font><br>\n\n" NAVI);

    for (i=0;i<=topfd;i++) {
        char* name=getname("D",i);
        if (!access(name,F_OK)) {
            FILE* f;
            f=fopen(name,"r");
            if (!f) pfatal("fopen");
            outf("<p>\n<a name=\"d%d\"><font color=green>File descriptor %d</font>:<p>\n",i,i);
            while (fgets(buf,sizeof(buf),f)) {
                outf("%s",buf);
            }
            unlink(name); fclose(f);
        }
    }

    debug("[+] Appending as-is trace output...\n");
    // negative
    // Tuesday, December 18, 2001
    // <!--- raw.txt --->
    outf("\n<!--- raw.txt --->\n<br>&nbsp;<p><hr><br><font size=+0><a name=A5><b>Trace output as-is:</b></font><br>\n\n" NAVI);
    outf("<pre><font face=\"lucida,courier,monospaced,fixed size=-2\">");

    cline=0;
    my_seek(0);
    while ((x=my_gets())) { cline++; outf("<a name=\"l%d\"><b>%07d</b>  %s\n",cline,cline,x); }

    outf("</pre>\n\n");

    outf(finito);

}

int main(const int argc, const char** argv) {

    debug("visualization for fenris -- <lcamtuf@coredump.cx>\n");

    if (argc!=3) usage(argv[0]);

    my_open(argv[1]);
    outfile=fopen(ofip=(char*)argv[2],"w");
    if (!outfile) pfatal(argv[2]);

    test_file();
    get_buffers();
    parse_functions();
    glue_together();

    fclose(outfile);

    debug("*** Done. Have a nice day!\n");

    return 0;

}

const static char spell2[] = "\n\n\n"
"It cannot be seen, cannot be felt,\n"
"Cannot be heard, cannot be smelt.\n"
"It lies behind stars and under hills,\n"
"And empty holes it fills.\n"
"It comes first and follows after,\n"
"Ends life, kills laughter.\n"
"\n\n\n";
