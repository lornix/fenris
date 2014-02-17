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

   "Almost anything derogatory you could say about today's software design
   would be accurate." -- K.E. Iverson

   I am not really very enthusiastic about putting all code in one file. But
   GCC is just a simple compiler, and it would not be able to perform proper
   inlining of functions that are in separate .c or .o files - and since this
   code consists of many small, frequently called functions, PUSH, CALL, POP
   and RET overhead might be noticeable.

   And remember: Soylent Green is people!

   Some code taken out by Marcin Gozdalik.

 */

#define _GNU_SOURCE

/* Hackish hack to import kernel stat struct without much collateral damage */

#define stat __kernel_stat
/* #define stat64 __kernel_stat64 */
/* #define old_stat __old_kernel_stat */
/* #define new_stat __kernel_stat */

#include <asm/stat.h>

#undef stat
/* #undef stat64 */
/* #undef old_stat */
/* #undef new_stat */

/* End of nasty hack. */

#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
// removed initially, possibly restore later
// #include "asmstring.h"
#include <fcntl.h>
#include <dlfcn.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <malloc.h>
#include <asm/types.h>
#include <utime.h>
#include <sys/resource.h>
#include <linux/types.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <grp.h>
#include <pwd.h>

#include <bfd.h>
// #include <libiberty.h>

#include "config.h"
#include "fenris.h"
#include "ioctls.h"
#include "libdisasm/libdis.h"
#include "fdebug.h"
#include "hooks.h"

// including allocs.h will automagically turn every malloc, realloc, free
// and strdup into my_malloc,my_realloc,my_free and my_strdup respectively
// you can override this by uncommenting the following line:
// #define USE_ORIGINAL_ALLOCS (but you don't want to do it for Fenris,
// otherwise, it'll break into tiny pieces and cut you badly).

#include "allocs.h"
#include "libfnprints.h"

#ifndef RTLD_NODELETE
// Damn damn damn. Bury me deep.
#define RTLD_NODELETE 0
#define DO_NOT_DLCLOSE 1
#endif /* not RTLD_NODELETE */

#define CURPCNT(x) current->pstack[current->nest][(int)current->pst_top[current->nest]+x]

char verybigbuf[200000];                    // output buffer

extern int break_stopped;                   // The process is stopped.
extern int break_continuing;

struct signed_user_regs_struct r;           // Current process: registers
unsigned char op[8];                        // Current process: rip[0..8]
int pid;                                    // Current process: pid
int in_libc;                                // Current process: rip in LIBCSEG?
unsigned int caddr;                         // Current process: CALL dest addr

unsigned int start_rip, stop_rip;

char fnm_buf[MAXDESCR];                     // Local function name

struct fenris_process ps[MAXCHILDREN];      // Traced process table
struct fenris_process *current;             // Currently traced process

char T_forks, T_execs, T_nocnd, T_nosym,    // Execution options
 T_noindent, T_nodesc, T_nomem, T_nosig, T_goaway,
    T_noskip, T_addip, T_atret = 2, T_wnow, T_alwaysret, *T_dostep, T_nolast;

unsigned char be_silent;

#ifdef HEAVY_DEBUG

unsigned int oldip;
unsigned char oldop[8];

#endif /* HEAVY_DEBUG */

char nonstd;
char is_static;
char already_main;
extern int blocking_syscall;

char *running_under_ncaegir;

int runasuid, runasgid;
char *runasuser;

FILE *ostream;                              // Output stream

int innest = PRETTYSMALL;
unsigned int STACKSEG, CODESEG;

// FIXME: hardcoded?!? more than 300+ for i386
const char *scnames[256] = {
    0,
#include "syscallnames.h"
    0
};

#define MPS (MAXFNAME*2)

char pdescr[MAXPDESC + 1];

struct hacking_table {
    unsigned int ip;
    unsigned int ad;
    unsigned char va;
};

struct hacking_table reptable[MAXREP];
unsigned int reptop = 0;

void nappend(char *dst, const char *src, int max)
{
    int i;
    i = max - strlen(dst) + 2;
    if (i <= 0)
        return;
    strncat(dst, src, i);
}

#define check_doret() if (current->doret) { debug("\n"); current->doret=0; }

char fatal_there;
extern int sd;
extern char break_shutup;

/************************************************************
 * This is our fatal error handling routine. We have three  *
 * kinds of call scenarios, self-explanatory.              *
 ************************************************************/

extern char test_leaks;

void fatal(const char *x, const int err)
{
    int i;

    if (T_dostep) {
        signal(SIGPIPE, SIG_IGN);
        break_shutup = 1;
        break_sendentity();
    }

    switch (err) {

        case -2:
        case -1:
            debug(">> Exit condition: %s\n", x);
            break;

        case 0:
            debug(">> Error condition: %s\n", x);
            break;

        default:
            debug(">> OS error       : %s [%d]\n" ">> Error condition: %s\n", strerror(err), err, x);

    }

    if (T_dostep && !fatal_there) {
        fatal_there = 1;
        break_sendentity_force();
    }

    if (pid > 0) {
        if (current && current->syscall) {
            debug(">> This condition occurred during syscall %s (%d) in pid %d (rip %llx).\n",
                  // FIXME: hardcoded?!? more than 300+ for i386
                  scnames[current->syscall & 0xff], current->syscall, pid, r.rip);
        } else {
            debug(">> This condition occurred while tracing pid %d (rip %llx).\n", pid, r.rip);
        }
    }

    if (current && (current->cycles))
        debug(">> Traced %u user CPU cycles (%d libcalls, %d fncalls, %d "
              "syscalls).\n", current->cycles, current->libcalls, current->fncalls, current->syscalls);

    if (err > -1)
        debug("\n**************************************************\n"
              "* If you believe this is because of programming  *\n"
              "* error, please report above message, along with *\n"
              "* information about your working environment and *\n"
              "* traced application, to the author of this      *\n"
              "* utility (e-mail: lcamtuf@coredump.cx). Thanks! *\n"
              "**************************************************\n\n");

    fflush(0);
    fclose(ostream);

    // If you go down in flames, aim for something expensive.
    for (i = 0; i < MAXCHILDREN; i++)
        if (ps[i].pid > 0)
            kill(ps[i].pid, 9);

    if (sd > 0) {
        shutdown(sd, 2);
        close(sd);
    }
    // for (i=3;i<128;i++) close(i);

    if (running_under_ncaegir) {
        char buf[100];
        printf("\033[0;37m\n\033[1;41mFenris has terminated, press RETURN to close...\033[0;37m\n");
        read(0, buf, sizeof(buf));
    }
#ifdef DEBUG
    if (err > -1)
        abort();
#endif /* DEBUG */

    exit(1);
}

/***********************************************
 * Produce nice graphical indentation and such *
 ***********************************************/

void indent(const int corr)
{
    char intbuf[MAXINDENT + 2];
    int tib;

    if (T_noindent)
        return;

    intbuf[0] = 0;

    if (current->nest >= 0) {

        tib = (corr + current->nest) > MAXINDENT ? MAXINDENT : (corr + current->nest);
        if (tib > 0) {
            memset(intbuf, ' ', tib);
            intbuf[tib] = 0;
        }

    }

    if (T_addip)
        debug("[%08llx] ", r.rip);

    if ((current->nest + corr) < 0)
        debug("%d:-- %s", pid, intbuf);
    else
        debug("%d:%02d %s", pid, corr + current->nest, intbuf);

}

/********************************************************
 * Here we simply execute what we have to execute after *
 * fork() and syncing with our parent process.          *
 ********************************************************/

extern int sd;                              // Debugger socket.

int start_child(const char **argv)
{
    int ret, n = 1;

    ret = fork();
    if (ret < 0)
        fatal("cannot fork", errno);
    if (ret) {
        pid = ret;
        return ret;
    }

    if (runasuser) {
        if (initgroups(runasuser, runasgid))
            fatal("initgroups failed", errno);
        if (setgid(runasgid))
            fatal("setgid failed", errno);
        if (setuid(runasuid))
            fatal("setuid failed", errno);
        debug("+++ [%s] Executing '%s", runasuser, argv[1]);
    } else
        debug("+++ Executing '%s", argv[1]);

    while (argv[++n])
        debug(" %s", argv[n]);
    debug("' (pid %d, %s) +++\n", getpid(), is_static ? "static" : "dynamic");

    fflush(0);

    {
        int i;
        // Close our own mess.
        for (i = 3; i < 64; i++)
            if (i != sd)
                close(i);
    }

    if (ptrace(PTRACE_TRACEME, 0, 0, 0))
        fatal("PTRACE_TRACEME failed", errno);
    execvp(argv[1], (void *)&argv[1]);
    perror(">> OS error      ");
    kill(getppid(), SIGUSR1);
    fatal("cannot execute requested binary", -1);
    return 0;                   // sanity.

}

/*************************
 * Remove signal handler *
 *************************/

unsigned int get_handler(int i)
{
    if (i < 0 || i >= MAXSIG)
        return 0;
    return current->sh[i];
}

/*******************************************
 * Temporarily remove int3 traps from code *
 *******************************************/

void remove_traps(void)
{
    int i;
    for (i = 0; i < MAXSIG; i++) {
        unsigned int addr = get_handler(i);

        if (!addr)
            return;

        if ((addr >> 24) == CODESEG || INLIBC(addr)) {
            unsigned int chg;
            chg = ptrace(PTRACE_PEEKDATA, pid, addr - 1, 0);
            if (current->shret[i])
                chg = (chg & 0xffffff00) + 0xc3;        /* c3: ret */
            else
                chg = (chg & 0xffffff00) + 0x90;        /* 90: nop */
            ptrace(PTRACE_POKEDATA, pid, addr - 1, chg);
        }
    }
}

/************************
 * Reinstall int3 traps *
 ************************/

void install_traps(void)
{
    int i;

    for (i = 0; i < MAXSIG; i++) {
        unsigned int addr = get_handler(i);

        if (!addr)
            return;

        if ((addr >> 28) == CODESEG || INLIBC(addr)) {
            unsigned int chg;
            chg = ptrace(PTRACE_PEEKDATA, pid, addr - 1, 0);

            chg = (chg & 0xffffff00) + 0xcc;    /* cc: int3 */
            ptrace(PTRACE_POKEDATA, pid, addr - 1, chg);
        }
    }
}

#define remove_handler(i) add_handler(i,0)

/**********************
 * Add signal handler *
 **********************/

void add_handler(int i, unsigned int a)
{
    if (i < 0 || i >= MAXSIG)
        return;
    current->sh[i] = a;
}

void set_withret(int i, char val)
{
    if (i < 0 || i >= MAXSIG)
        return;
    current->shret[i] = val;
}

/*************************
 * Lookup memory address *
 *************************/

struct fenris_mem *lookup_mem(const unsigned int addr)
{
    unsigned int i;

    for (i = 0; i < current->memtop; i++) {

        if (!(*current->mem)[i].descr)
            continue;
        if ((*current->mem)[i].addr <= addr)
            if (((*current->mem)[i].addr + (*current->mem)[i].len) > addr) {
                return &(*current->mem)[i];
            }
    }

    return 0;
}

/****************************************
 * Lookup any buffer inside given range *
 ****************************************/

struct fenris_mem *lookup_inrange(const unsigned int addr, const unsigned int len)
{
    unsigned int end = addr + len;
    unsigned int i;

    for (i = 0; i < current->memtop; i++) {

        if (!(*current->mem)[i].descr)
            continue;

        if ((*current->mem)[i].addr >= addr)
            if ((*current->mem)[i].addr < end)
                if ((*current->mem)[i].addr + (*current->mem)[i].len >= addr)
                    if ((*current->mem)[i].addr + (*current->mem)[i].len < end)
                        return &(*current->mem)[i];

    }

    return 0;

}

/*************************************
 * Find or assign unique function id *
 *************************************/

int find_id(unsigned int c, unsigned int addnew)
{
    unsigned int i;

    if (!current->fnaddr) {
        if (!addnew)
            return 0;
        current->fnaddr = malloc(TABINC * 4 + 4);
    }

    for (i = 0; i < current->idtop; i++)
        if ((*current->fnaddr)[i] == c)
            return i + 1;

    if (!addnew)
        return 0;

    current->idtop++;

    if (!((current->idtop) % TABINC))
        current->fnaddr = realloc(current->fnaddr, (current->idtop + 1 + TABINC) * 4);

    (*current->fnaddr)[current->idtop - 1] = c;

    return current->idtop;

}

/************************
 * Lookup function name *
 ************************/

char *lookup_fnct(unsigned int c, unsigned int add, char prec)
{
    unsigned int i;
    int mindif = 100000000, best = -1;
    int addplus = 0;

    if (add == 123456) {
        add = 0;
        addplus = 1;
    }

    if (add) {
        find_id(c, 1);
    }

    if (!current->b) {

        int size;
        bfd *b;

        if (current->symfail || T_nosym) {
            // Do not retry.
            if (!find_id(c, 0))
                return 0;
            sprintf(fnm_buf, "fnct_%d", find_id(c, 0));
            return fnm_buf;
        }

        sprintf(fnm_buf, "/proc/%d/exe", pid);
        b = bfd_openr(fnm_buf, 0);

        if (!b) {
            current->symfail = 1;
            if (!find_id(c, 0))
                return 0;
            sprintf(fnm_buf, "fnct_%d", find_id(c, 0));
            return fnm_buf;
        }

        if (bfd_check_format(b, bfd_archive)) {
            current->symfail = 1;
            if (!find_id(c, 0))
                return 0;
            sprintf(fnm_buf, "fnct_%d", find_id(c, 0));
            bfd_close(b);
            return fnm_buf;
        }

        bfd_check_format_matches(b, bfd_object, 0);

        if ((bfd_get_file_flags(b) & HAS_SYMS) == 0) {
            current->symfail = 1;
            if (!find_id(c, 0))
                return 0;
            sprintf(fnm_buf, "fnct_%d", find_id(c, 0));
            bfd_close(b);
            return fnm_buf;
        }

        size = bfd_get_symtab_upper_bound(b);

        if (size <= 0) {
            current->symfail = 1;
            if (!find_id(c, 0))
                return 0;
            sprintf(fnm_buf, "fnct_%d", find_id(c, 0));
            bfd_close(b);
            return fnm_buf;
        }

        current->syms = (asymbol **) malloc(size);

        if (!current->syms) {
            current->symfail = 1;
            if (!find_id(c, 0))
                return 0;
            sprintf(fnm_buf, "fnct_%d", find_id(c, 0));
            bfd_close(b);
            return fnm_buf;
        }
        // FIXME: can't fail, unsigned values
        /* 
         * if ((current->symcnt=bfd_canonicalize_symtab(b,current->syms))<0)
         *     fatal("bfd_canonicalize_symtab failed",0);
         */

        current->b = b;

    }

    for (i = 0; i < current->symcnt; i++)
        if (current->syms[i] && (current->syms[i]->flags != 1)) {
            if (prec) {
                if (bfd_asymbol_value(current->syms[i]) != c)
                    continue;
                if (!bfd_asymbol_name(current->syms[i]) || !strlen(bfd_asymbol_name(current->syms[i])))
                    continue;
            } else {
                int dif;
                dif = c - (bfd_asymbol_value(current->syms[i]));
                if (dif < 0)
                    continue;
                if (!bfd_asymbol_name(current->syms[i]) || !strlen(bfd_asymbol_name(current->syms[i])))
                    continue;
                if (dif <= mindif) {
                    mindif = dif;
                    best = i;
                }
                if (dif)
                    continue;
            }

            strcpy(fnm_buf, bfd_asymbol_name(current->syms[i]));

            if (fnm_buf[0])
                return fnm_buf;

        }

    if ((!prec) && (best > 0)) {
        strcpy(fnm_buf, bfd_asymbol_name(current->syms[best]));
        if (addplus)
            sprintf(&fnm_buf[strlen(fnm_buf)], "+%d", mindif);
        return fnm_buf;
    }

    if (!find_id(c, 0))
        return 0;
    sprintf(fnm_buf, "fnct_%d", find_id(c, 0));
    return fnm_buf;

}

/***************************
 * Try to find symbol name *
 ***************************/

Dl_info di;
char fn_buf[64];

char *find_name(const unsigned int addr)
{

    unsigned int i;

    for (i = 0; i < current->mtop + 1; i++) {

        if (!(*current->map)[i].name)
            continue;
        if ((*current->map)[i].addr <= addr) {
            if (((*current->map)[i].addr + (*current->map)[i].len) > addr) {

                void *x;
                unsigned int off;
                unsigned long int b;
                int f;

                off = addr - (*current->map)[i].addr;

                // Offset 0x10 should be equal to 0x03. Otherwise, we do not
                // want to dlopen() this "thing".

                f = open((*current->map)[i].name, O_RDONLY);
                if (f < 0) {
                    sprintf(fn_buf, "P:lib_%x", addr);
                    return fn_buf;
                }

                lseek(f, 0x10, SEEK_SET);
                read(f, fn_buf, 1);
                close(f);
                if (fn_buf[0] != 0x03) {
                    sprintf(fn_buf, "S:lib_%x", addr);
                    return fn_buf;
                }

                if (T_nosym)
                    x = 0;
                else
                    x = dlopen((*current->map)[i].name, RTLD_LAZY | RTLD_GLOBAL | RTLD_NODELETE);

                if (!x) {
                    sprintf(fn_buf, "L:lib_%x", addr);
                    return fn_buf;
                }

                b = *((int *)x) + off;

                if (!dladdr((void *)b, &di)) {
                    dlclose(x);
                    sprintf(fn_buf, "A:lib_%x", current->lentry);
                    return fn_buf;
                }

                if (!di.dli_sname) {
#ifndef DO_NOT_DLCLOSE
                    dlclose(x);
#endif
                    sprintf(fn_buf, "<unnamed:%lx>%+ld", (unsigned long int)di.dli_saddr,
                            b - (unsigned long int)di.dli_saddr);
                    return fn_buf;
                }

                if (di.dli_saddr != (void *)b) {
#ifndef DO_NOT_DLCLOSE
                    dlclose(x);
#endif
                    snprintf(fn_buf, sizeof(fn_buf), "%s%+ld", di.dli_sname, b - (unsigned long int)di.dli_saddr);
                    return fn_buf;
                }
#ifndef DO_NOT_DLCLOSE
                dlclose(x);
#endif
                return (char *)di.dli_sname;

            }

        }

    }

    sprintf(fn_buf, "F:lib_%x", addr);
    return fn_buf;

}

char *find_name_ex(unsigned int c, char prec, char non)
{
    char *ret = find_name(c);
    if (non)
        if (strchr(ret, ':'))
            return 0;
    if (prec == 1) {
        if (strchr(ret, '+'))
            return 0;
        if (strchr(ret, '-'))
            return 0;
    } else if (prec == 2) {
        char *q;
        if ((q = strchr(ret, '+')))
            *q = 0;
        if ((q = strchr(ret, '-')))
            *q = 0;
    }
    return ret;
}

/*******************************************
 * Add or update memory region information *
 *******************************************/

void add_mem(unsigned int start, int len, unsigned int newaddr, const char *who, char auth)
{

    unsigned int i;
    char *doingmerge = 0;
    unsigned int owner = 0;
    char U = 0;
    char buf[MAXDESCR], b2[MAXDESCR];
    struct fenris_mem *f;

    if (current->nest < 0)
        return;                 // No, sorry.

    if (len <= 0)
        return;                 // Sorry even more.

    if (start + len < start)
        fatal("start + len < start in add_mem", 0);

    if (!start || (start > 0xffffff00))
        return;

    if (newaddr == 2) {
        newaddr = 0;
        U = 1;
    }

    if (newaddr) {

        // We have some authoritative buffer size readjustment.
        // Expect finding buffer with matching address. In
        // emergency, you might have to create new buffer description.

        f = lookup_mem(start);

        if (!f) {

            // Oh man.
            if (!U) {
                indent(0);
                debug("- remap: non-existing buffer %x -> %x:%d\n", start, newaddr, len);
            } else {
                sprintf(b2, "- remap: non-existing buffer %x -> %x:%d\n", start, newaddr, len);
                nappend(pdescr, b2, MAXDESCR);
            }

            if (!current->memtop) {
                current->memtop = TABINC;
                current->mem = malloc(sizeof(struct fenris_mem) * TABINC);
            }

            for (i = 0; i < current->memtop; i++)
                if (!(*current->mem)[i].descr)
                    break;

            if (i == current->memtop) {
                current->memtop += TABINC;
                current->mem = realloc(current->mem, sizeof(struct fenris_mem) * (current->memtop + 1));
            }

            snprintf(buf, MAXDESCR, "from hell, resized in %s", who);
            (*current->mem)[i].descr = strdup(buf);
            (*current->mem)[i].addr = newaddr;
            (*current->mem)[i].len = len;
            (*current->mem)[i].owner = current->fntop;
            return;

        }

        if ((f->addr != start)) {
            if (!U) {
                indent(0);
                debug("- remap: %x -> %x:%d, but nearest is: %x:%d (%s)\n", start, newaddr, len, f->addr, f->len,
                      f->descr);
            } else {
                sprintf(b2, "- remap: %x -> %x:%d, but nearest is: %x:%d (%s)\n", start, newaddr, len, f->addr, f->len,
                        f->descr);
                nappend(pdescr, b2, MAXDESCR);
            }
            return;
        }

        if (!U) {
            indent(0);
            debug("\\ remap: %x:%d -> %x:%d\n", f->addr, f->len, newaddr, len);
        } else {
            sprintf(b2, "\\ remap: %x:%d -> %x:%d\n", f->addr, f->len, newaddr, len);
            nappend(pdescr, b2, MAXDESCR);
        }

        snprintf(buf, MAXDESCR, "resized from %d in %s", f->len, who);
        free(f->descr);
        f->descr = strdup(buf);
        f->len = len;
        f->addr = newaddr;
        f->auth = auth;

    } else {

      mergeloop:

        f = lookup_inrange(start, len);

        if (f) {
            if (!T_nodesc) {
                if (f->auth) {
                    if (!U) {
                        indent(0);
                        debug("\\ UNEXPECTED is-within: %x:%d in %x:%d (%s)\n", f->addr, f->len, start, len, f->descr);
                    } else {
                        sprintf(b2, "\\ UNEXPECTED is-within: %x:%d in %x:%d (%s)\n", f->addr, f->len, start, len,
                                f->descr);
                        nappend(pdescr, b2, MAXDESCR);
                    }
                }
                if (!U) {
                    indent(0);
                    debug("\\ discard: mem %x:%d (%s) [is within %x:%d]\n", f->addr, f->len, f->descr, start, len);
                } else {
                    sprintf(b2, "\\ discard: mem %x:%d (%s) [is within %x:%d]\n", f->addr, f->len, f->descr, start,
                            len);
                    nappend(pdescr, b2, MAXDESCR);
                }
            }

            f->addr = 0;
            free(f->descr);
            if (f->lasti)
                free(f->lasti);
            f->lasti = 0;
            f->descr = 0;
            f->len = 0;

            f = 0;
            goto mergeloop;
        }

        if (!auth)
            f = lookup_mem(start + len + 1);
        else
            f = 0;
        if (!f)
            f = lookup_mem(start + len);

        if (f) {
            if (f->addr <= start) {

                // So, we have a buffer that starts before ours and ends
                // past our buffer. It looks like there is no need to do
                // anything,
                // unless this is an authoritative attempt.

                if (auth && (!T_nodesc)) {
                    if (!U) {
                        indent(0);
                        debug("\\ UNEXPECTED already-have: %x:%d in %x:%d (%s)\n", start, len, f->addr, f->len,
                              f->descr);
                    } else {
                        sprintf(b2, "\\ UNEXPECTED already-have: %x:%d in %x:%d (%s)\n", start, len, f->addr, f->len,
                                f->descr);
                        nappend(pdescr, b2, MAXDESCR);
                    }
                }

                if (doingmerge)
                    free(doingmerge);
                return;

            } else {

                // We have something that starts in our buffer and ends past
                // our buffer. Adjust current length and discard the old one.

                if (auth)
                    if (start + len + 1 == f->addr)
                        goto nojoin;

                if (!T_nodesc) {
                    if (!U) {
                        if (!(auth | f->auth) && !be_silent) {
                            indent(0);
                            debug("\\ %smerge [EA]: %x:%d %x:%d (%s) -> ", (auth | f->auth) ? "UNEXPECTED " : "", start,
                                  len, f->addr, f->len, f->descr);
                        }
                    } else {
                        sprintf(b2, "\\ %smerge [EA]: %x:%d %x:%d (%s) -> ", (auth | f->auth) ? "UNEXPECTED " : "",
                                start, len, f->addr, f->len, f->descr);
                        nappend(pdescr, b2, MAXDESCR);
                    }
                }

                len = f->len;
                len += (f->addr - start);
                if (f->auth)
                    auth = 1;
                if (doingmerge)
                    free(doingmerge);
                doingmerge = f->descr;
                owner = f->owner;
                f->addr = f->len = 0;
                f->descr = 0;
                f->auth = 0;

                if (!T_nodesc) {
                    if (!U) {
                        if (!(auth | f->auth) && !be_silent)
                            debug("%x:%d\n", start, len);
                    } else {
                        sprintf(b2, "%x:%d\n", start, len);
                        nappend(pdescr, b2, MAXDESCR);
                    }
                }
                // Retry, we might have more things like that.
                goto mergeloop;

            }

        }

        if (!auth)
            f = lookup_mem(start - 1);
        else
            f = 0;
        if (!f)
            f = lookup_mem(start);

        if (f) {
            // Ok, so we have a buffer that contains our start point.
            // Check where would it end.

            if ((f->addr + f->len) >= (start + len)) {

                // Ah, so this buffer starts before ours and ends past this
                // point.

                if (auth && (!T_nodesc)) {
                    if (!U) {
                        indent(0);
                        debug("\\ UNEXPECTED already-have: %x:%d in %x:%d (%s)\n", start, len, f->addr, f->len,
                              f->descr);
                    } else {
                        sprintf(b2, "\\ UNEXPECTED already-have: %x:%d in %x:%d (%s)\n", start, len, f->addr, f->len,
                                f->descr);
                        nappend(pdescr, b2, MAXDESCR);
                    }
                }

                if (doingmerge)
                    free(doingmerge);
                return;

            } else {

                // The buffer starts before ours and ends inside ours.
                // Resize our, discard the old one.

                if (auth)
                    if (f->addr + f->len + 1 == start)
                        goto nojoin;

                if (!T_nodesc) {
                    if (!U) {
                        if (!(auth | f->auth) && !be_silent) {
                            indent(0);
                            debug("\\ %smerge [SB]: %x:%d %x:%d (%s) -> ", (auth | f->auth) ? "UNEXPECTED " : "", start,
                                  len, f->addr, f->len, f->descr);
                        }
                    } else {
                        sprintf(b2, "\\ %smerge [SB]: %x:%d %x:%d (%s) -> ", (auth | f->auth) ? "UNEXPECTED " : "",
                                start, len, f->addr, f->len, f->descr);
                        nappend(pdescr, b2, MAXDESCR);
                    }
                }

                len = f->len + len - ((f->addr + f->len) - start);
                start = f->addr;
                if (f->auth)
                    auth = 1;
                if (doingmerge)
                    free(doingmerge);
                doingmerge = f->descr;
                owner = f->owner;
                f->addr = f->len = 0;
                f->descr = 0;
                f->auth = 0;

                if (!T_nodesc) {
                    if (!U) {
                        if (!(auth | f->auth) && !be_silent)
                            debug("%x:%d\n", start, len);
                    } else {
                        sprintf(b2, "%x:%d\n", start, len);
                        nappend(pdescr, b2, MAXDESCR);
                    }
                }

                goto mergeloop;

            }
        }

      nojoin:

        if (!current->memtop) {
            current->memtop = TABINC;
            current->mem = malloc(sizeof(struct fenris_mem) * TABINC);
        }

        for (i = 0; i < current->memtop; i++)
            if (!(*current->mem)[i].descr)
                break;

        if (i == current->memtop) {
            current->memtop += TABINC;
            current->mem = realloc(current->mem, sizeof(struct fenris_mem) * current->memtop);
        }

        if (!doingmerge) {
            snprintf(buf, MAXDESCR, "first seen in %s", who);
            (*current->mem)[i].descr = strdup(buf);
            (*current->mem)[i].owner = current->fntop;
        } else {
            (*current->mem)[i].descr = doingmerge;
            (*current->mem)[i].owner = owner;
        }

        (*current->mem)[i].addr = start;
        (*current->mem)[i].len = len;
        (*current->mem)[i].auth = auth;

        if (!doingmerge && !T_nodesc) {
            if (!U) {
                char *x = lookup_fnct(start, 0, 0);
                if (!x)
                    x = find_name_ex(start, 2, 1);

                if (!be_silent) {
                    indent(0);
                    if ((x = lookup_fnct(start, 0, 0)))
                        debug("\\ new %sbuffer candidate: %x:%d (%s)\n", auth ? "authoritative " : "", start, len, x);
                    else
                        debug("\\ new %sbuffer candidate: %x:%d\n", auth ? "authoritative " : "", start, len);
                }
            } else {
                char *x = lookup_fnct(start, 0, 0);
                if (!x)
                    x = find_name_ex(start, 2, 1);

                if (x)
                    sprintf(b2, "\\ new %sbuffer candidate: %x:%d (%s)\n", auth ? "authoritative " : "", start, len, x);
                else
                    sprintf(b2, "\\ new %sbuffer candidate: %x:%d\n", auth ? "authoritative " : "", start, len);
                nappend(pdescr, b2, MAXDESCR);
            }
        }
    }

}

/*****************************
 * Add something to writelog *
 *****************************/

void append_wlog(const char *what)
{
    int curlen = 0;

    if (T_wnow) {
        if (strchr(what, '*'))
            indent(0);
        debug("%s", what);
        return;
    }

    if (current->wlog[current->fntop]) {
        curlen = strlen((char *)current->wlog[current->fntop]);
        if (strstr((char *)current->wlog[current->fntop], what))
            return;
    }
    current->wlog[current->fntop] = realloc(current->wlog[current->fntop], curlen + strlen(what) + 4);
    strcat((char *)current->wlog[current->fntop], what);
}

void *libc_sym;

// Used only for debugging. Be careless.
int lookup_fnname(char *name)
{
    unsigned int i;
    char fnm_buf[1000];
    char *fifi;
    int add = 0;

    fifi = strchr(name, '+');

    if (fifi) {
        *fifi = 0;
        fifi++;
        sscanf(fifi, "%d", &add);
    }
    // First, try the simplest solution.
    if (sscanf(name, "fnct_%d", &i) == 1) {
        if (current->fnaddr) {
            --i;
            if (i > 0 && i < current->idtop)
                return (*current->fnaddr)[i] + add;
        }
        return 0;
    }

    if (T_nosym)
        return 0;

    // Then, try libc...
    if (!libc_sym) {
        if (!is_static)
            libc_sym = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
        if (!libc_sym)
            goto no_libc;
    }

    i = (unsigned long int)dlsym(libc_sym, name);
    if (i)
        return i + add;

  no_libc:

    // Nope. Try local symbols

    if (!current->b) {

        int size;
        bfd *b;

        if (current->symfail)
            return 0;

        sprintf(fnm_buf, "/proc/%d/exe", pid);
        b = bfd_openr(fnm_buf, 0);

        if (!b) {
            current->symfail = 1;
            return 0;
        }

        if (bfd_check_format(b, bfd_archive)) {
            current->symfail = 1;
            bfd_close(b);
            return 0;
        }

        bfd_check_format_matches(b, bfd_object, 0);

        if ((bfd_get_file_flags(b) & HAS_SYMS) == 0) {
            current->symfail = 1;
            bfd_close(b);
            return 0;
        }

        size = bfd_get_symtab_upper_bound(b);

        if (size <= 0) {
            current->symfail = 1;
            bfd_close(b);
            return 0;
        }

        current->syms = (asymbol **) malloc(size);

        if (!current->syms) {
            current->symfail = 1;
            bfd_close(b);
            return 0;
        }
        // FIXME: unsigned < 0 always false
        /* 
         * if ((current->symcnt=bfd_canonicalize_symtab(b,current->syms))<0)
         *     fatal("bfd_canonicalize_symtab failed",0);
         */

        current->b = b;

    }

    for (i = 0; i < current->symcnt; i++)
        if (current->syms[i])
            if (bfd_asymbol_name(current->syms[i]))
                if (!strcmp(bfd_asymbol_name(current->syms[i]), name))
                    return bfd_asymbol_value(current->syms[i]) + add;

    return 0;

}

/***********************
 * Remove memory block *
 ***********************/

void delete_mem(unsigned int start, char auth)
{
    struct fenris_mem *f;

    f = lookup_mem(start);
    if (!f) {
        if (!auth)
            return;
        indent(0);
        debug("- discard on non-existing block %x\n", start);
        return;
    }

    if (!T_nodesc) {
        indent(0);
        debug("\\ discard: mem %x:%d (%s)\n", f->addr, f->len, f->descr);
    }

    f->addr = 0;
    free(f->descr);
    if (f->lasti)
        free(f->lasti);
    f->lasti = 0;
    f->descr = 0;
    f->len = 0;

}

/********************
 * Die mysteriously *
 ********************/

void segfault(int x __attribute__ ((unused)))
{

    debug("Fatal exception occurred. Fenris will terminate now. If you feel\n"
          "this should not happen, please use fenris-bug application to\n"
          "report this problem to the maintainer. Thank you :-)\n\n");

    if (current) {
        debug("Fault parameters: pid:%d rip:%llx rsp:%llx nest:%d memtop:%d\n"
              "\tidtop:%d mtop:%d memtop:%d fntop:%d symcnt:%d\n\n",
              current->pid, r.rip, r.rsp, current->nest, current->memtop,
              current->idtop, current->mtop, current->memtop, current->fntop, current->symcnt);
    }

    abort();
}

void pipefault(int x __attribute__ ((unused)))
{
    fatal("connection dropped? terminal disappeared?", -1);
}

/**************
 * Lookup map *
 **************/

struct fenris_map *lookup_map(const unsigned int addr)
{
    unsigned int i;

    for (i = 0; i < current->mtop + 1; i++) {

        if (!(*current->map)[i].name)
            continue;
        if ((*current->map)[i].addr <= addr)
            if (((*current->map)[i].addr + (*current->map)[i].len) > addr)
                return &(*current->map)[i];

    }

    return 0;

}

/******************************
 * Mark local regions invalid *
 ******************************/

void invalidate_mem(void)
{
    unsigned int i;
    unsigned int s;

    for (i = 0; i < current->memtop; i++) {
        if ((s = (*current->mem)[i].addr)) {
            if ((s >> 24) != STACKSEG)
                continue;
            // if (s >= current->frstart[current->fntop])
            if (s < current->frend[current->fntop])
                delete_mem(s, 1);
        }
    }

}

/**************************************
 * Push local function entry to stack *
 **************************************/

void push_fnid(const unsigned int id)
{

    if (current->fntop >= MAXNEST) {
        if (T_noskip) {
            debug("* WARNING: fntop MAXNEST exceeded at 0x%llx, pretending that nothing happened.\n", r.rip);
            current->fntop--;
        } else
            fatal("fntop MAXNEST exceeded", 0);
    }

    current->frstart[current->fntop] = r.rsp + current->curpcnt * 4;

    current->fntop++;
    current->fnid[current->fntop] = id;
    current->fnrip[current->fntop] = r.rip;

    current->frstart[current->fntop] = 0;
    current->frend[current->fntop] = r.rsp + 4;

}

/*******************************
 * Add something to pdescr log *
 *******************************/

void add_pdescr(const unsigned int q)
{
    int miau = 0;
    char tmp[MAXDESCR];
    struct fenris_map *ma = 0;
    struct fenris_mem *me = 0;

    if (T_dostep) {
        if ((q >> 24) == CODESEG)
            break_memread(q);
        else if ((q >> 24) == STACKSEG)
            break_memread(q);
        else if (INLIBC(q))
            break_memread(q);
    }

    if (T_nodesc)
        return;

    if ((q >> 24) == CODESEG)
        miau = 1;               // global
    else if ((q >> 24) == STACKSEG)
        miau = 2;               // local
    else if (INLIBC(q))
        miau = 3;               // shared
    else
        return;

    tmp[0] = 0;

    // First of all, it might be a local function. Look for exact match.

    if (miau == 1) {
        if (lookup_fnct(q, 0, 1)) {
            sprintf(tmp, "+ g/%x = local %s\n", q, lookup_fnct(q, 0, 1));
            nappend(pdescr, tmp, MAXPDESC);
        }
    }
    // Then, it can be a library function. Check for exact match, again.

    else if (miau == 3) {
        char *x;
        current->lentry = q;
        x = find_name_ex(q, 1, 1);
        if (x) {
            snprintf(tmp, MAXDESCR, "+ s/%x = %s\n", q, x);
            nappend(pdescr, tmp, MAXPDESC);
        }
    }
    // Hmm, look for unspecific stuff - is this a buffer? Or a map?

    if (miau) {
        me = lookup_mem(q);
        if (me) {
            if (!tmp[0]) {
                snprintf(tmp, MAXDESCR, "+ %x = %x:%d <off %d> (%s)\n", q, me->addr, me->len, q - me->addr, me->descr);
                nappend(pdescr, tmp, MAXPDESC);
            } else {
                sprintf(tmp, ":%d\n", me->len);
                pdescr[strlen(pdescr) - 1] = 0;
                nappend(pdescr, tmp, MAXPDESC);
            }
            if (me->lasti) {
                snprintf(tmp, MAXDESCR, "  last input: %s\n", me->lasti);
                nappend(pdescr, tmp, MAXPDESC);
            }
            return;
        }
        if (!me)
            ma = lookup_map(q);
        if (ma) {
            if (!tmp[0]) {
                snprintf(tmp, MAXDESCR, "+ %x = map %x:%d <off %d> (%s)\n", q,
                         ma->addr, ma->len, q - ma->addr, ma->descr);
                nappend(pdescr, tmp, MAXPDESC);
            }
            if (ma->lasti) {
                snprintf(tmp, MAXDESCR, "  last input: %s\n", ma->lasti);
                nappend(pdescr, tmp, MAXPDESC);
            }
            return;
        }
    }

    if (tmp[0])
        return;

    // Last resort: try do determine where does it point on stack, if
    // it does point there.

    if (miau == 2) {
        unsigned int i;
        for (i = 1; i <= current->fntop; i++) {
            if (q >= current->frstart[i])
                if (q < current->frend[i]) {
                    // Wow, something local.

                    sprintf(tmp, "+ l/%x (maxsize %d) = stack of fcnt_%d (%d down)\n",
                            q, current->frend[i] - q, current->fnid[i], current->fntop - i);

                    nappend(pdescr, tmp, MAXPDESC);
                    return;

                }

        }

    }
    // Giving up.

    return;

}

/***********************
 * Add unknown filedes *
 ***********************/

void unknown_filedes(const int fd, const char *fname)
{

    char tmpbuf[MAXDESCR];

    if (!current->fd) {
        current->fd = malloc(TABINC * sizeof(struct fenris_fd));
        current->fdtop = TABINC;
    }

    while (current->fdtop <= (unsigned int)fd) {
        current->fdtop += TABINC;
        current->fd = realloc(current->fd, current->fdtop * sizeof(struct fenris_fd));
    }

    (*current->fd)[fd].special = 0;
    (*current->fd)[fd].name = strdup(fname);

    snprintf(tmpbuf, MAXDESCR, "origin unknown");

    (*current->fd)[fd].descr = strdup(tmpbuf);
    (*current->fd)[fd].p = 0;

}

/***************
 * Describe fd *
 ***************/

void add_fd_pdescr(const int fd)
{
    char tmp[MAXDESCR];

    if (T_nodesc)
        return;

    if ((fd < 0) || ((unsigned int)fd >= current->fdtop)) {
        char buf[100];
        sprintf(buf, "/proc/%d/fd/%d", current->pid, fd);
        if (fd == 0 || fd == 1 || fd == 2 || !access(buf, F_OK)) {
            char b[1024];
            bzero(b, sizeof(b));
            readlink(buf, b, 1000);
            sprintf(tmp, "+ fd %d: \"%s\", origin unknown\n", fd, b);
            nappend(pdescr, tmp, MAXPDESC);
            unknown_filedes(fd, b);
        }
        return;
    }

    if (!((*current->fd)[fd].name)) {
        char buf[100];
        sprintf(buf, "/proc/%d/fd/%d", current->pid, fd);
        if (fd == 0 || fd == 1 || fd == 2 || !access(buf, F_OK)) {
            char b[1024];
            bzero(b, sizeof(b));
            readlink(buf, b, 1000);
            sprintf(tmp, "+ fd %d: \"%s\", origin unknown\n", fd, b);
            nappend(pdescr, tmp, MAXPDESC);
            unknown_filedes(fd, b);
        }
        return;
    }

    sprintf(tmp, "+ fd %d: \"%s\", %s\n", fd, (*current->fd)[fd].name, (*current->fd)[fd].descr);

    nappend(pdescr, tmp, MAXPDESC);

    // What are you looking for here, you poor little lost soul?
    // But since you're already here, what would you say for a
    // little trivia? http://lcamtuf.coredump.cx/simple.txt :-)

}

unsigned int appr_addr(const unsigned int addr)
{

    char fn_buf[64];
    unsigned int i;

    for (i = 0; i < current->mtop + 1; i++) {

        if (!(*current->map)[i].name)
            continue;
        if ((*current->map)[i].addr <= addr) {
            if (((*current->map)[i].addr + (*current->map)[i].len) > addr) {

                void *x;
                unsigned int off;
                unsigned long int b;
                int f;

                off = addr - (*current->map)[i].addr;

                f = open((*current->map)[i].name, O_RDONLY);
                if (f < 0)
                    return addr;

                lseek(f, 0x10, SEEK_SET);
                read(f, fn_buf, 1);
                close(f);
                if (fn_buf[0] != 0x03)
                    return addr;

                if (T_nosym)
                    x = 0;
                else
                    x = dlopen((*current->map)[i].name, RTLD_LAZY | RTLD_GLOBAL | RTLD_NODELETE);

                if (!x)
                    return addr;

                b = *((int *)x) + off;

                if (!dladdr((void *)b, &di)) {
                    dlclose(x);
                    return addr;
                }

                dlclose(x);
                return (unsigned long int)di.dli_saddr;

            }

        }

    }

    return addr;

}

/****************
 * Get filename *
 ****************/

char *get_fname(const int fd)
{

    if ((fd < 0) || ((unsigned int)fd >= current->fdtop))
        return "<unknown>";

    if (!(*current->fd)[fd].name)
        return "<unknown>";

    return (*current->fd)[fd].name;

}

/*********************************************
 * Modify last input parameter for SOMETHING *
 *********************************************/

void modify_lasti(unsigned int sth, char *where, int fd, unsigned int map, char *what)
{
    char buf[MAXDESCR * 2];
    struct fenris_map *ma = 0;
    struct fenris_mem *me = 0;

    if (!sth || (sth > 0xffffff00))
        return;

    strncpy(buf, where, MAXDESCR);

    if (map)
        sprintf(&buf[strlen(buf)], " on map %x", map);
    else if (fd)
        sprintf(&buf[strlen(buf)], " on file \"%s\"", get_fname(fd));
    else if (what && what[0])
        snprintf(&buf[strlen(buf)], MAXDESCR, " on %s", what);

    me = lookup_mem(sth);

    if (me) {
        if (me->lasti)
            free(me->lasti);
        me->lasti = strdup(buf);
        if (current->nest >= 0 && !be_silent) {
            indent(0);
            debug("\\ buffer %x modified.\n", me->addr);
        }
        return;
    }

    ma = lookup_map(sth);

    if (ma) {
        if (ma->lasti)
            free(ma->lasti);
        ma->lasti = strdup(buf);
        if (current->nest >= 0 && !be_silent) {
            indent(0);
            debug("\\ buffer %x modified.\n", ma->addr);
        }
        return;
    }
    // Doh. Nothing.
}

/********************************************
 * Add description of given addr to the log *
 ********************************************/

void add_wdescr(unsigned int q, char wri)
{
    int miau = 0;
    char tmp[MAXDESCR];
    struct fenris_map *ma = 0;
    struct fenris_mem *me = 0;
    char b2[64];

    if (T_nodesc)
        return;

    if ((q >> 24) == CODESEG)
        miau = 1;               // global
    else if ((q >> 24) == STACKSEG)
        miau = 2;               // local
    else if (INLIBC(q))
        miau = 3;               // shared
    else
        return;

    if (current->idtop)
        sprintf(b2, "%s", lookup_fnct((*current->fnaddr)[current->idtop - 1], 0, 1));
    else
        strcpy(b2, "main");

    be_silent = 1;
    add_mem(q, 4, 0, b2, 0);
    be_silent = 0;

    tmp[0] = 0;

    // First of all, it might be a local function. Look for exact match.

    if (miau == 1) {
        if (lookup_fnct(q, 0, 0)) {
            sprintf(tmp, "* %s local object %s ~%x)\n", wri ? "WRITE" : "READ", lookup_fnct(q, 0, 0),
                    find_id(q, 0) ? (*current->fnaddr)[find_id(q, 0) - 1] : q);
            append_wlog(tmp);
        }
    }
    // Then, it can be a library function. Check for exact match, again.

    else if (miau == 3) {
        char *x;
        current->lentry = q;
        x = find_name_ex(q, 2, 1);
        if (x) {
            sprintf(tmp, "* %s shared object %s ~%x)\n", wri ? "WRITE" : "READ", x, appr_addr(q));
            append_wlog(tmp);
        }
    }

    if (tmp[0]) {
        be_silent = 1;
        if (wri)
            modify_lasti(q, b2, 0, 0, 0);
        be_silent = 0;
        return;
    }
    // Hmm, look for unspecific stuff - is this a buffer? Or a map?

    if (miau) {
        me = lookup_mem(q);
        if (me) {
            snprintf(tmp, MAXDESCR, "* %s buffer~%x\n", wri ? "WRITE" : "READ", me->addr);
            append_wlog(tmp);
            be_silent = 1;
            if (wri)
                modify_lasti(q, b2, 0, 0, 0);
            be_silent = 0;
            return;
        }
        if (!me)
            ma = lookup_map(q);
        if (ma) {
            snprintf(tmp, MAXDESCR, "* %s map~%x:%d (%s)\n", wri ? "WRITE" : "READ", ma->addr, ma->len, ma->descr);
            append_wlog(tmp);
            be_silent = 1;
            if (wri)
                modify_lasti(q, b2, 0, 0, 0);
            be_silent = 0;
            return;
        }
    }
    // Last resort: try do determine where does it point on stack, if
    // it does point there.

    if (miau == 2) {
        unsigned int i;
        for (i = 1; i <= current->fntop; i++) {

            if (q >= current->frstart[i])
                if (q < current->frend[i]) {
                    // Wow, something local.

                    sprintf(tmp, "* %s stack of fcnt_%d (%d down)\n", wri ? "WRITE" : "READ",
                            current->fnid[i], current->fntop - i);

                    append_wlog(tmp);
                    be_silent = 1;
                    if (wri)
                        modify_lasti(q, b2, 0, 0, 0);
                    be_silent = 0;
                    return;

                }

        }

    }

    fatal("brain damage", 0);
    return;

}

/**************************************
 * Some fast-action debug() functions *
 **************************************/

unsigned int Xv(const unsigned int q)
{
    if (q)
        add_pdescr(q);
    return q;
}

int Xf(int q)
{
    if (q >= 0)
        add_fd_pdescr(q);
    return q;
}

unsigned int Wv(const unsigned int q)
{
    if (q)
        add_wdescr(q, 1);
    return q;
}

/****************
 * Write pdescr *
 ****************/

void dump_pdescr(const int ind)
{
    char *x = pdescr, *old;

    if (!pdescr[0])
        return;
    if (T_nodesc)
        return;

    while ((x = strchr(old = x, '\n'))) {
        indent(ind);
        *x = 0;
        debug("%s\n", old);
        x++;
    }

    pdescr[0] = 0;

}

/**************
 * Write wlog *
 **************/

void dump_memchg(const int ind)
{
    char *x = (char *)current->wlog[current->fntop], *old, *y;

    if (!x)
        return;
    if (T_nodesc)
        return;

    indent(ind);
    debug("// function has accessed non-local memory:\n");
    pdescr[0] = 0;

    while ((x = strchr(old = x, '\n'))) {
        indent(ind);
        *x = 0;
        if ((y = strchr(old, '~'))) {
            unsigned int addr;
            if (*(y - 1) == ' ')
                *y = '(';
            else
                *y = ' ';
            if (sscanf(y + 1, "%x", &addr) == 1)
                Xv(addr);
        }
        debug("%s\n", old);
        dump_pdescr(ind);
        x++;
    }

    free(current->wlog[current->fntop]);
    current->wlog[current->fntop] = 0;

}

/******************************
 * Return from local function *
 ******************************/

void fn_ret(void)
{

    if (current->fntop > 0) {
        dump_memchg(0);
        invalidate_mem();
        current->fntop--;
        return;
    }

}

/*****************
 * Add map entry *
 *****************/

void add_map(const int fd, const unsigned int addr, const unsigned int len, char *who)
{

    unsigned int i;
    char *file;
    char *descr = "<ERROR>";
    char tmpbuf[MAXDESCR];

    if (fd > 0)
        if ((unsigned int)fd >= current->fdtop)
            fatal("excessive fd in add_map", 0);

    if (!current->map)
        current->map = malloc(TABINC * sizeof(struct fenris_map));

    for (i = 0; i < current->mtop; i++)
        if (!((*current->map)[i].name))
            break;

    if (i == current->mtop) {
        if (i)
            i++;
        current->mtop++;

        if (!((current->mtop) % TABINC))
            current->map = realloc(current->map, (current->mtop + 1 + TABINC) * sizeof(struct fenris_map));

    }

    if (fd < 0) {
        if (current->nest <= 0)
            file = "/lib/ld-linux.so.2";
        else
            file = "<anonymous>";
    } else {
        file = (*current->fd)[fd].name;
        if (!file)
            file = "<unknown>";
    }

    (*current->map)[i].name = strdup(file);
    (*current->map)[i].addr = addr;
    (*current->map)[i].len = len;

    if (fd < 0) {
        if (current->nest <= 0)
            strcpy(tmpbuf, "mapped in kernel");
        else
            snprintf(tmpbuf, MAXDESCR, "anon-mapped in %s", who);
    } else {
        descr = (*current->fd)[fd].descr;
        if (!descr)
            descr = "fd origin unknown";
        snprintf(tmpbuf, MAXDESCR, "%s, mapped in %s", descr, who);
    }

    (*current->map)[i].descr = strdup(tmpbuf);

    if (current->nest >= 0) {
        indent(0);
        debug("\\ new map: %x:%d (%s)\n", addr, len, (*current->map)[i].name);
    }

}

/**************************
 * Add default linker map *
 **************************/

void add_ldmap(void)
{
    unsigned int st, en;
    char buf[MAXDESCR + 1];
    FILE *x = fopen("/proc/self/maps", "r");
    if (!x)
        fatal("cannot open /proc/self/maps", errno);
    buf[MAXDESCR] = 0;
    while (fgets(buf, MAXDESCR, x)) {
        if (sscanf(buf, "%x-%x", &st, &en) != 2)
            fatal("/proc/self/maps format error", 0);
        if (INLIBC(st)) {
            fclose(x);
            add_map(-1, st, en - st, "<linker>");
            return;
        }
    }
    fatal("cannot find ld-linux.so.2 in /proc/self/maps", 0);
}

/******************************
 * Add new pupils to ps table *
 ******************************/

void add_process(const int mpid)
{
    int i;

    for (i = 0; i < MAXCHILDREN; i++)

        if (!ps[i].pid) {
            bzero(&ps[i], sizeof(struct fenris_process));
            ps[i].pid = mpid;
            ps[i].nest = innest;
            ps[i].is_static = is_static;
            current = &ps[i];
            add_ldmap();
            return;
        }

    fatal("too many child processes (table overflow)", 0);

}

int issuit(const char c)
{
    if (isprint(c))
        return 1;
    if ( /* c=='\n' || */ c == '\t')
        return 1;
    return 0;
}

void print_string(const unsigned int addr, const char *where)
{
    char b[5] = { 0, 0, 0, 0, 0 };
    int miau = 0;
    AS_UINT(b) = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (issuit(b[0]) && issuit(b[1]) && issuit(b[2]) && issuit(b[3])) {
        debug(" \"%s", b);
        miau = 4;
        while (strlen(b) == 4) {
            AS_UINT(b) = ptrace(PTRACE_PEEKDATA, pid, addr + miau, 0);
            if (b[0] && !isprint(b[0]))
                b[0] = '?';
            if (b[1] && !isprint(b[1]))
                b[1] = '?';
            if (b[2] && !isprint(b[2]))
                b[2] = '?';
            if (b[3] && !isprint(b[3]))
                b[3] = '?';
            if (miau < MAXUNKNOWN)
                debug("%s", b);
            miau += strlen(b);
        }
        debug("\"");
        if (miau >= MAXUNKNOWN)
            debug("...");
    }
    if (miau)
        add_mem(addr, miau + 1, 2, where, 0);
}

/********************************
 * Describe function parameters *
 ********************************/

void display_value(const unsigned int q, const char *where)
{

    if ((q >> 24) == CODESEG)
        debug("g/%x", q);       // global
    else if ((q >> 24) == STACKSEG)
        debug("l/%x", q);       // local
    else if (INLIBC(q))
        debug("s/%x", q);       // shared
    else
        debug("%d", q);

    add_pdescr(q);
    print_string(q, where);

}

char *get_addrdescr(const unsigned int q)
{
    int miau = 1;
    char tmp[MAXDESCR];
    static char ret[MAXDESCR];
    struct fenris_map *ma = 0;
    struct fenris_mem *me = 0;

    ret[0] = 0;

    if (miau) {
        me = lookup_mem(q);
        if (me) {
            if (!tmp[0]) {
                snprintf(tmp, MAXDESCR, "+ %x = %x:%d <off %d> (%s)\n", q, me->addr, me->len, q - me->addr, me->descr);
                nappend(ret, tmp, MAXPDESC);
            } else {
                sprintf(tmp, ":%d\n", me->len);
                pdescr[strlen(pdescr) - 1] = 0;
                nappend(ret, tmp, MAXPDESC);
            }
            if (me->lasti) {
                snprintf(tmp, MAXDESCR, "  last input: %s\n", me->lasti);
                nappend(ret, tmp, MAXPDESC);
            }
        }
        if (!me)
            ma = lookup_map(q);
        if (ma) {
            if (!tmp[0]) {
                snprintf(tmp, MAXDESCR, "+ %x = map %x:%d <off %d> (%s)\n", q,
                         ma->addr, ma->len, q - ma->addr, ma->descr);
                nappend(ret, tmp, MAXPDESC);
            }
            if (ma->lasti) {
                snprintf(tmp, MAXDESCR, "  last input: %s\n", ma->lasti);
                nappend(ret, tmp, MAXPDESC);
            }
        }
    }
    // Last resort: try do determine where does it point on stack, if
    // it does point there.

    if ((q >> 24) == STACKSEG) {
        unsigned int i;
        for (i = 1; i <= current->fntop; i++) {
            if (q >= current->frstart[i])
                if (q < current->frend[i]) {
                    sprintf(tmp, "+ l/%x (maxsize %d) = stack of fcnt_%d (%d down)\n",
                            q, current->frend[i] - q, current->fnid[i], current->fntop - i);

                    nappend(ret, tmp, MAXPDESC);
                }
        }
    }

    return ret;

}

char *get_fddescr(const int fd)
{
    char tmp[MAXDESCR];
    static char ret[MAXDESCR];

    ret[0] = 0;

    if ((fd < 0) || ((unsigned int)fd >= current->fdtop) || !((*current->fd)[fd].name)) {
        char buf[100];
        sprintf(buf, "/proc/%d/fd/%d", current->pid, fd);
        if (fd == 0 || fd == 1 || fd == 2 || !access(buf, F_OK)) {
            char b[1024];
            bzero(b, sizeof(b));
            readlink(buf, b, 1000);
            sprintf(tmp, "+ fd %d: \"%s\", origin unknown\n", fd, b);
            nappend(ret, tmp, MAXPDESC);
            return ret;
        }
        return "";
    }

    sprintf(tmp, "+ fd %d: \"%s\", %s\n", fd, (*current->fd)[fd].name, (*current->fd)[fd].descr);

    nappend(ret, tmp, MAXPDESC);
    return ret;

}

/*********************************
 * Read stack and display params *
 *********************************/

void display_fparams(unsigned int esP, int pcnt, const char *where)
{
    int i;
    unsigned int q;
    pdescr[0] = 0;
    for (i = 0; i < pcnt; i++) {
        q = ptrace(PTRACE_PEEKDATA, pid, esP + 4 * i, 0);
        display_value(q, where);
        if (i != pcnt - 1)
            debug(", ");
    }
}

void warn_opt(int d, int p)
{
    if (d != p) {
        current->bopt++;
        if (!current->Owarn) {
            current->Owarn = 1;
            debug(""
                  "**********************************************************\n"
                  "* This function is supposed to have different number of  *\n"
                  "* parameters than I've detected. Because this particular *\n"
                  "* library call is known to me, it will be displayed      *\n"
                  "* properly - however, parameter number auto-detection    *\n"
                  "* for unknown library calls and local functions might be *\n"
                  "* inaccurate. This is very likely to be a result of high *\n"
                  "* optimization of traced binary. Try documentation.      *\n"
                  "**********************************************************\n");
        }
    } else
        current->gopt++;
}

/*********************************
 * Get string from ptraced child *
 *********************************/

void get_string_from_child(const unsigned int addr, char *buf, int max)
{
    int i = 0;
    char *b = buf;

    while (b < buf + max) {
        AS_UINT(*b) = ptrace(PTRACE_PEEKDATA, pid, addr + i, 0);

        // FIXME: no, really.. how does an UINT == -1?
        /* 
         * if (AS_UINT(*b)==-1) {
         *     *b=0;
         *     return; // Lame, but what can I do? For strings, acceptable.
         * }
         */

        if (b[0] && ((!isprint(b[0])) || (b[0] == '"')))
            b[0] = '?';
        if (b[1] && ((!isprint(b[1])) || (b[1] == '"')))
            b[1] = '?';
        if (b[2] && ((!isprint(b[2])) || (b[2] == '"')))
            b[2] = '?';
        if (b[3] && ((!isprint(b[3])) || (b[3] == '"')))
            b[3] = '?';
        if (!(b[0] && b[1] && b[2] && b[3]))
            return;
        b += 4;
        i += 4;
    }

    buf[max - 1] = 0;

}

/*****************************************
 * Try to find a match for this function *
 *****************************************/

void display_specific(void)
{

    char n[MAXDESCR];
    char *f = (char *)current->lcname;
    char buf[MAXDESCR];
    char b2[MAXDESCR];

    if (current->idtop)
        sprintf(n, "L %s:%s", lookup_fnct((*current->fnaddr)[current->idtop - 1], 0, 1), f);
    else
        sprintf(n, "L main:%s", f);

    debug("L %s (", f);

    pdescr[0] = 0;

    if (!strcmp(f, "strlen")) {
        get_string_from_child(current->lcpar[0], buf, sizeof(buf));
        debug("%x \"%s\")", Xv(current->lcpar[0]), buf);
        debug(" = %lld\n", r.rax);
        dump_pdescr(0);
        warn_opt(1, current->lcpcnt);
        add_mem(current->lcpar[0], r.rax + 1, 0, n, 0);
    }

    else if (!strcmp(f, "malloc")) {
        debug("%d)", current->lcpar[0]);
        debug(" = %llx\n", r.rax);
        dump_pdescr(0);
        warn_opt(1, current->lcpcnt);
        if (r.rax)
            add_mem(r.rax, current->lcpar[0], 0, n, 1);
    }

    else if (!strcmp(f, "strdup")) {
        get_string_from_child(current->lcpar[0], buf, sizeof(buf));
        debug("%x \"%s\")", Xv(current->lcpar[0]), buf);
        debug(" = %llx\n", r.rax);
        dump_pdescr(0);
        warn_opt(1, current->lcpcnt);
        if (r.rax)
            add_mem(r.rax, strlen(buf), 0, n, 1);
    }

    else if (!strcmp(f, "calloc")) {
        debug("%d, %d)", current->lcpar[0], current->lcpar[1]);
        debug(" = %llx\n", r.rax);
        dump_pdescr(0);
        warn_opt(2, current->lcpcnt);
        if (r.rax)
            add_mem(r.rax, current->lcpar[0] * current->lcpar[1], 0, n, 1);
    }

    else if (!strcmp(f, "realloc")) {
        debug("%x, %d)", Xv(current->lcpar[0]), current->lcpar[1]);
        debug(" = %llx\n", r.rax);
        dump_pdescr(0);
        warn_opt(2, current->lcpcnt);
        if (current->lcpar[0]) {
            if (r.rax)
                add_mem(current->lcpar[0], current->lcpar[1], r.rax, n, 1);
        } else {
            if (r.rax)
                add_mem(r.rax, current->lcpar[1], 0, n, 1);
        }
    }

    else if (!strcmp(f, "free")) {
        debug("%x) = <void>\n", Xv(current->lcpar[0]));
        dump_pdescr(0);
        warn_opt(1, current->lcpcnt);
        delete_mem(current->lcpar[0], 1);
    }

    else if (!strcmp(f, "getenv")) {
        get_string_from_child(current->lcpar[0], buf, sizeof(buf));
        if (r.rax)
            get_string_from_child(r.rax, b2, sizeof(buf));
        debug("%x \"%s\") = %llx", Xv(current->lcpar[0]), buf, r.rax);
        if (r.rax)
            debug("\"%s\"\n", b2);
        else
            debug("\n");
        dump_pdescr(0);
        warn_opt(1, current->lcpcnt);
        add_mem(current->lcpar[0], strlen(buf) + 1, 0, n, 0);
        add_mem(r.rax, strlen(b2) + 1, 0, n, 0);
    }

    else if (!strcmp(f, "atexit")) {
        debug("%x) = %lld\n", Xv(current->lcpar[0]), r.rax);
        dump_pdescr(0);
        debug("*******************************************************\n"
              "* In some cases, atexit() statement can be not traced *\n"
              "* properly (see documentation).                       *\n"
              "*******************************************************\n");
        warn_opt(1, current->lcpcnt);
    }

    else if (!strcmp(f, "strcpy")) {
        get_string_from_child(current->lcpar[1], b2, sizeof(buf));
        debug("%x, %x \"%s\") = %llx\n", Xv(current->lcpar[0]), Xv(current->lcpar[1]), b2, r.rax);
        dump_pdescr(0);
        warn_opt(2, current->lcpcnt);
        add_mem(current->lcpar[0], strlen(b2) + 1, 0, n, 0);
        add_mem(current->lcpar[1], strlen(b2) + 1, 0, n, 0);
        modify_lasti(current->lcpar[0], n, 0, 0, 0);
        indent(0);
        debug("\\ data migration: %x to %x\n", current->lcpar[1], current->lcpar[0]);
    }

    else if (!strcmp(f, "memcpy") || !strcmp(f, "memmove")) {
        debug("%x, %x, %d) = %llx\n", Xv(current->lcpar[0]), Xv(current->lcpar[1]), current->lcpar[2], r.rax);
        dump_pdescr(0);
        warn_opt(3, current->lcpcnt);
        add_mem(current->lcpar[0], current->lcpar[2], 0, n, 0);
        add_mem(current->lcpar[1], current->lcpar[2], 0, n, 0);
        modify_lasti(current->lcpar[0], n, 0, 0, 0);
        indent(0);
        debug("\\ data migration: %x to %x\n", current->lcpar[1], current->lcpar[0]);
    }

    else if (!strcmp(f, "memset")) {
        debug("%x, %x, %d) = %llx\n", Xv(current->lcpar[0]), current->lcpar[1], current->lcpar[2], r.rax);
        dump_pdescr(0);
        warn_opt(3, current->lcpcnt);
        add_mem(current->lcpar[0], current->lcpar[2], 0, n, 0);
        modify_lasti(current->lcpar[0], n, 0, 0, 0);
        indent(0);
    }

    else if (!strcmp(f, "bzero")) {
        debug("%x, %d) = %llx\n", Xv(current->lcpar[0]), current->lcpar[1], r.rax);
        dump_pdescr(0);
        warn_opt(2, current->lcpcnt);
        add_mem(current->lcpar[0], current->lcpar[1], 0, n, 0);
        modify_lasti(current->lcpar[0], n, 0, 0, 0);
    }

    else if (!strcmp(f, "bcopy")) {
        debug("%x, %x, %d) = %llx\n", Xv(current->lcpar[0]), Xv(current->lcpar[1]), current->lcpar[2], r.rax);
        dump_pdescr(0);
        warn_opt(3, current->lcpcnt);
        add_mem(current->lcpar[0], current->lcpar[2], 0, n, 0);
        add_mem(current->lcpar[1], current->lcpar[2], 0, n, 0);
        modify_lasti(current->lcpar[1], n, 0, 0, 0);
        indent(0);
        debug("\\ data migration: %x to %x\n", current->lcpar[0], current->lcpar[1]);
    }

    else if (!strcmp(f, "memcmp") || !strcmp(f, "bcmp")) {
        debug("%x, %x, %d) = %llx\n", Xv(current->lcpar[0]), Xv(current->lcpar[1]), current->lcpar[2], r.rax);
        dump_pdescr(0);
        warn_opt(3, current->lcpcnt);
        add_mem(current->lcpar[0], current->lcpar[2], 0, n, 0);
        add_mem(current->lcpar[1], current->lcpar[2], 0, n, 0);
    }

    else if (!strcmp(f, "getc")) {
        FILE x;
        int fd;
        long int off = ((unsigned long int)&x._fileno - (unsigned long int)&x);
        fd = ptrace(PTRACE_PEEKDATA, pid, current->lcpar[0] + off, 0);
        debug("%x [%d]) = '%c' %lld\n", Xv(current->lcpar[0]),
              Xf(fd), isprint(r.rax) ? (unsigned char)r.rax : '?', r.rax);
        dump_pdescr(0);
        warn_opt(1, current->lcpcnt);
        add_mem(current->lcpar[0], sizeof(x), 0, n, 0);
    }

    else if (!strcmp(f, "strcmp")) {
        get_string_from_child(current->lcpar[0], buf, sizeof(buf));
        get_string_from_child(current->lcpar[1], b2, sizeof(buf));
        debug("%x \"%s\", %x \"%s\") = %llx\n", current->lcpar[0], buf, current->lcpar[1], b2, r.rax);
        dump_pdescr(0);
        warn_opt(2, current->lcpcnt);
        add_mem(current->lcpar[0], strlen(buf) + 1, 0, n, 0);
        add_mem(current->lcpar[1], strlen(b2) + 1, 0, n, 0);
    }

    else if (!strcmp(f, "strncmp")) {
        get_string_from_child(current->lcpar[0], buf, sizeof(buf));
        get_string_from_child(current->lcpar[1], b2, sizeof(buf));
        debug("%x \"%s\", %x \"%s\", %d) = %llx\n", Xv(current->lcpar[0]), buf,
              Xv(current->lcpar[1]), b2, current->lcpar[2], r.rax);
        dump_pdescr(0);
        warn_opt(3, current->lcpcnt);
        add_mem(current->lcpar[0], strlen(buf) + 1, 0, n, 0);
        add_mem(current->lcpar[1], strlen(b2) + 1, 0, n, 0);
    }

    else if (!strcmp(f, "strncpy")) {
        get_string_from_child(current->lcpar[1], b2, sizeof(buf));
        debug("%x, %x \"%s\", %d) = %llx\n", Xv(current->lcpar[0]),
              Xv(current->lcpar[1]), b2, current->lcpar[2], r.rax);
        dump_pdescr(0);
        warn_opt(3, current->lcpcnt);
        add_mem(current->lcpar[0], current->lcpar[2], 0, n, 0);
        add_mem(current->lcpar[1], strlen(b2) + 1, 0, n, 0);
        modify_lasti(current->lcpar[0], n, 0, 0, 0);
        indent(0);
        debug("\\ data migration: %x to %x\n", current->lcpar[1], current->lcpar[0]);
    }

    else
        fatal("display_specific called on something non-specific", 0);

    pdescr[0] = 0;

}

/*****************************************************************
 * Check if we handle this one separately, save all the stuff... *
 *****************************************************************/

char check_specific(char *n, unsigned int esP, int pcnt)
{
    int i;

    if (strcmp(n, "strlen"))
        if (strcmp(n, "getenv"))
            if (strcmp(n, "strcpy"))
                if (strcmp(n, "memcpy"))
                    if (strcmp(n, "strdup"))
                        if (strcmp(n, "calloc"))
                            if (strcmp(n, "malloc"))
                                if (strcmp(n, "realloc"))
                                    if (strcmp(n, "free"))
                                        if (strcmp(n, "getc"))
                                            if (strcmp(n, "strcmp"))
                                                if (strcmp(n, "strncmp"))
                                                    if (strcmp(n, "strncpy"))
                                                        if (strcmp(n, "atexit"))
                                                            if (strcmp(n, "memmove"))
                                                                if (strcmp(n, "memset"))
                                                                    if (strcmp(n, "bzero"))
                                                                        if (strcmp(n, "bcopy"))
                                                                            if (strcmp(n, "memcmp"))
                                                                                if (strcmp(n, "bcmp"))

                                                                                    return 0;

    strncpy((char *)current->lcname, n, MAXNAME);
    current->lcpcnt = pcnt;

    for (i = 0; i < MAXPARS; i++)
        current->lcpar[i] = ptrace(PTRACE_PEEKDATA, pid, esP + i * 4, 0);

    return 1;

}

/*********************
 * Clean up old mess *
 *********************/

void remove_process(void)
{
    int i;

    if (!current)
        fatal("trying to remove process but current is NULL", 0);

    if (current->gopt + current->bopt)
        debug("+++ Parameter prediction %0.2f%% successful [%d:%d] +++\n",
              100.0 * ((float)current->gopt) / ((float)(current->gopt + current->bopt)), current->bopt, current->gopt);

    if (T_dostep)
        break_exitcond();

    for (i = 0; i < MAXNEST; i++) {
        if (current->wlog[i])
            free(current->wlog[i]);
    }

    if (current->mem) {
        unsigned int i;
        for (i = 0; i < current->memtop; i++)
            if ((*current->mem)[i].descr)
                free((*current->mem)[i].descr);
        for (i = 0; i < current->memtop; i++)
            if ((*current->mem)[i].lasti)
                free((*current->mem)[i].lasti);
        free(current->mem);
    }

    if (current->b)
        bfd_close(current->b);
    if (current->syms)
        free(current->syms);

    if (current->map) {
        unsigned int i;
        for (i = 0; i < current->mtop + 1; i++) {
            if ((*current->map)[i].name)
                free((*current->map)[i].name);
            if ((*current->map)[i].descr)
                free((*current->map)[i].descr);
            if ((*current->map)[i].lasti)
                free((*current->map)[i].lasti);
        }
        free(current->map);
    }

    if (current->fd) {
        unsigned int i;
        for (i = 0; i < current->fdtop; i++) {
            if ((*current->fd)[i].name)
                free((*current->fd)[i].name);
            if ((*current->fd)[i].descr)
                free((*current->fd)[i].descr);
        }
        free(current->fd);
    }

    if (current->fnaddr)
        free(current->fnaddr);
    bzero(current, sizeof(struct fenris_process));
    current = 0;

}

/********************************************
 * Duplicate some structures. I do not even *
 * want to think how would it look like for *
 * partially shared process info (clone()). *
 ********************************************/

void clone_process(const int newpid)
{
    int i;
    struct fenris_process *p;

    if (!current)
        fatal("trying to clone process but current is NULL", 0);

    p = current;
    add_process(newpid);
    memcpy(current, p, sizeof(struct fenris_process));
    current->pid = newpid;
    current->syscall = 0;

    for (i = 0; i < MAXNEST; i++) {
        if (current->wlog[i])
            current->wlog[i] = strdup(current->wlog[i]);
    }

    if (current->mem) {
        unsigned int i;
        current->mem = malloc((1 + TABINC + current->memtop) * sizeof(struct fenris_mem));
        memcpy(current->mem, p->mem, (1 + TABINC + current->memtop) * sizeof(struct fenris_mem));
        for (i = 0; i < current->memtop; i++) {
            if ((*p->mem)[i].descr)
                (*current->mem)[i].descr = strdup((*p->mem)[i].descr);
            if ((*p->mem)[i].lasti)
                (*current->mem)[i].lasti = strdup((*p->mem)[i].lasti);
        }
    }

    if (current->map) {
        unsigned int i;
        current->map = malloc((1 + TABINC + current->mtop) * sizeof(struct fenris_map));
        memcpy(current->map, p->map, (1 + TABINC + current->mtop) * sizeof(struct fenris_map));
        for (i = 0; i < current->mtop; i++) {
            if ((*p->map)[i].descr)
                (*current->map)[i].descr = strdup((*p->map)[i].descr);
            if ((*p->map)[i].name)
                (*current->map)[i].name = strdup((*p->map)[i].name);
            if ((*p->map)[i].lasti)
                (*current->map)[i].lasti = strdup((*p->map)[i].lasti);
        }
    }

    if (current->fd) {
        unsigned int i;
        current->fd = malloc((1 + TABINC + current->fdtop) * sizeof(struct fenris_fd));
        memcpy(current->fd, p->fd, (TABINC + current->fdtop + 1) * sizeof(struct fenris_fd));
        for (i = 0; i < current->fdtop; i++) {
            if ((*p->fd)[i].descr)
                (*current->fd)[i].descr = strdup((*p->fd)[i].descr);
            if ((*p->fd)[i].name)
                (*current->fd)[i].name = strdup((*p->fd)[i].name);
        }
    }

    if (current->fnaddr) {
        current->fnaddr = malloc((1 + TABINC + current->idtop) * sizeof(int));
        memcpy(current->fnaddr, p->fnaddr, current->idtop * sizeof(int));
    }

    current->b = 0;
    current->syms = 0;

    current = p;

}

/****************************
 * Get memory from child :> *
 ****************************/

void get_mem_from_child(const unsigned int addr, char *buf, int max)
{
    int i = 0;
    char *b = buf;

    while (max % 4)
        max--;

    while (b < buf + max) {
        AS_UINT(*b) = ptrace(PTRACE_PEEKDATA, pid, addr + i, 0);
        b += 4;
        i += 4;
    }

}

/*******************
 * Check for error *
 *******************/

char errbuf[64];

char *toerror(int q)
{
    if (q < 0)
        sprintf(errbuf, "%d (%s)", q, strerror(-q));
    else
        sprintf(errbuf, "%d", q);
    return errbuf;
}

/************************
 * Quick fork() handler *
 ************************/

void trace_fork(void)
{

    int p = 0, q = 0, ser;
    unsigned long int off;
    struct user u;

    off = (unsigned long int)&u.regs.rax - (unsigned long int)&u;
    errno = 1234;
    // This is the speed zone.
    ptrace(PTRACE_SINGLESTEP, pid, 1, 0);
    while (errno)
        p = ptrace(PTRACE_PEEKUSER, pid, off, errno = 0);
    if (p > 0)
        q = ptrace(PTRACE_ATTACH, p, 0, 0);
    // End of speed zone.

    ser = errno;
    indent(0);
    debug("%sfork () = %s\n", in_libc ? "[L] " : "", toerror((int)p));

    if (q)
        fatal("PTRACE_ATTACH failed", ser);
    debug("+++ New process %d attached +++\n", p);
    clone_process(p);
    r.rax = p;

}

/****************************************************
 * Handle int $0x80 calls - no matter why and where *
 ****************************************************/

void want_ret(void)
{
    current->syscall = r.rax;
    memcpy(&current->pr, &r, sizeof(r));
}

/********************
 * "Before" handler *
 ********************/

void handle_syscall(void)
{
    char buf[MAXFNAME];
    unsigned int addr;

    if (current->nest >= -1)
        current->syscalls++;

    switch (r.rax) {

        case __NR_clone:

            debug("***************************************************************\n"
                  "* This application uses clone(). This is probably  a sign of  *\n"
                  "* multi-threaded application. Multi-threading involves shared *\n"
                  "* memory segments, file descriptors and such, and I am not    *\n"
                  "* able to handle it properly for now. Sorry...                *\n"
                  "***************************************************************\n");

            fatal("clone() is not supported", 0);

            break;

        case __NR_fork:
        case __NR_vfork:

            if (T_forks)
                trace_fork();
            else {
                remove_traps();
                want_ret();
            }
            break;

        case __NR_exit:

            indent(0);
            debug("%sSYS exit (%lld) = ???\n", in_libc ? "[L] " : "", r.rbx);

            while (--current->nest >= -1) {
                indent(0);
                debug("...function never returned (program exited before).\n");
                if (current->nest < 0 || current->isfnct[current->nest]) {
                    dump_memchg(0);
                    if (current->fntop)
                        current->fntop--;
                }
                if (T_dostep)
                    break_nestdown();
            }

            break;

        case __NR_execve:

            indent(0);

            get_string_from_child(r.rbx, buf, MAXFNAME);

            pdescr[0] = 0;

            debug("%sSYS execve (%x \"%s\", 0x%x, 0x%x) = ", in_libc ? "[L] " : "",
                  Xv(r.rbx), buf, Xv(r.rcx), Xv(r.rdx));

            dump_pdescr(0);

            current->syscall = __NR_execve;
            break;

        case __NR_sigaction:
        case __NR_rt_sigaction:

            // Modify address in memory structure.
            addr = ptrace(PTRACE_PEEKDATA, pid, r.rcx, 0);

            if (!addr)
                break;

            if ((addr >> 24) == CODESEG) {
                ptrace(PTRACE_POKEDATA, pid, r.rcx, addr - 1);
            } else {
                break;
            }

            goto aftersig;

        case __NR_signal:

            // Simply adjust address in register.
            addr = r.rcx;

            if (!addr)
                break;
            if ((addr >> 24) == CODESEG || INLIBC(addr)) {
                r.rcx--;
            } else {
                break;
            }

            ptrace(PTRACE_SETREGS, pid, 0, &r);
            r.rcx++;
            // So __NR_signal handler won't have to do anything.

          aftersig:

            // Inject int3 into code.
            if (addr)
                if ((addr >> 24) == CODESEG || INLIBC(addr)) {
                    unsigned int chg, c2;
                    chg = ptrace(PTRACE_PEEKDATA, pid, addr - 1, 0);
                    if ((current->signals < r.rbx) && (r.rbx < MAXSIG))
                        current->signals = r.rbx;

                    if (((chg & 0xff) != 0x90) && ((chg & 0xff) != 0xc3) && ((chg & 0xff) != 0xcc)) {
                        c2 = ptrace(PTRACE_PEEKDATA, pid, addr - 3, 0);
                        if ((c2 & 0xffffff) != 0x00768d)        // Stupid gcc
                                                                // -O9 lea
                            debug("* WARNING: Handler for sig %lld (%x) w/o leading NOP or RET, problems!\n", r.rbx,
                                  addr);
                    }

                    if ((chg & 0xff) == 0xc3) {
                        set_withret(r.rbx, 1);
                    } else {
                        if ((chg & 0xff) == 0x90) {
                            set_withret(r.rbx, 0);
                        }
                    }
                    chg = (chg & 0xffffff00) + 0xcc;    /* cc: int3 */
                    ptrace(PTRACE_POKEDATA, pid, addr - 1, chg);

                }

        default:
            want_ret();

    }

    if (T_dostep && current) {
        fflush(0);
        break_syscall(r.rax);
    }

}

/************************
 * Add item to fd table *
 ************************/

void add_filedes(const int fd, const char *fname, char *who, int p)
{

    char tmpbuf[MAXDESCR];

    if (!current->fd) {
        current->fd = malloc(TABINC * sizeof(struct fenris_fd));
        current->fdtop = TABINC;
    }

    while (current->fdtop <= (unsigned int)fd) {
        current->fdtop += TABINC;
        current->fd = realloc(current->fd, current->fdtop * sizeof(struct fenris_fd));
    }

    (*current->fd)[fd].special = 0;
    (*current->fd)[fd].name = strdup(fname);

    snprintf(tmpbuf, MAXDESCR, "opened in %s", who);

    (*current->fd)[fd].descr = strdup(tmpbuf);
    (*current->fd)[fd].p = p;

    if (current->nest >= -1 && !T_nodesc) {
        indent(0);
        debug("@ created fd %d (%s)\n", fd, fname);
    }

}

/*****************************
 * Remove item from fd table *
 *****************************/

void remove_filedes(const int fd)
{

    if ((fd >= 0) && ((unsigned int)fd < current->fdtop) && (*current->fd)[fd].name) {

        if (current->nest >= -1 && !T_nodesc) {
            indent(0);
            debug("@ removed fd %d (%s)\n", fd, (*current->fd)[fd].name);
        }

        free((*current->fd)[fd].name);
        free((*current->fd)[fd].descr);
        (*current->fd)[fd].name = 0;
        (*current->fd)[fd].descr = 0;

    }

}

/**********************
 * Duplicate filedes. *
 **********************/

void dup_filedes(const int old, const int fd, char *who)
{
    char tmpbuf[MAXDESCR];

    if (current->fdtop <= (unsigned int)old)
        fatal("dup_filedes with excessive fd", 0);
    if (old < 0 || fd < 0)
        fatal("dup_filedes with excessive fd", 0);

    while (current->fdtop <= (unsigned int)fd) {
        current->fdtop += TABINC;
        current->fd = realloc(current->fd, current->fdtop * sizeof(struct fenris_fd));
    }

    if ((*current->fd)[fd].name) {
        pdescr[0] = 0;
        Xf(fd);
        dump_pdescr(0);
        remove_filedes(fd);
    }

    if (!(*current->fd)[old].name)
        (*current->fd)[fd].name = strdup("<unknown>");
    else
        (*current->fd)[fd].name = strdup((*current->fd)[old].name);

    snprintf(tmpbuf, MAXDESCR, "cloned in %s", who);
    (*current->fd)[fd].descr = strdup(tmpbuf);
    (*current->fd)[fd].p = (*current->fd)[old].p;

    if (current->nest >= -1 && !T_nodesc) {
        indent(0);
        debug("@ new duplicate fd %d from %d (%s)\n", fd, old, (*current->fd)[fd].name);
    }

}

/***********************
 * Change filedes info *
 ***********************/

void modify_filedes(const int fd, const char *newt, int newp)
{

    if ((fd >= 0) && ((unsigned int)fd < current->fdtop) && (*current->fd)[fd].name) {

        if (newt) {
            free((*current->fd)[fd].name);
            (*current->fd)[fd].name = strdup(newt);
        }

        if (newp)
            (*current->fd)[fd].p = newp;

    }

}

/***************************
 * Get .p parameter (port) *
 ***************************/

int get_filep(const int fd)
{

    if ((fd >= 0) && ((unsigned int)fd < current->fdtop) && (*current->fd)[fd].name)
        return (*current->fd)[fd].p;

    return 0;

}

/********************
 * Delete map entry *
 ********************/

void delete_map(const unsigned int addr)
{
    unsigned int i;
    for (i = 0; i < current->mtop + 1; i++)
        if ((*current->map)[i].addr == addr) {
            if (current->nest >= -1) {
                if (!T_nodesc) {
                    indent(0);
                    debug("\\ discard: map %x, \"%s\", %s\n", addr, (*current->map)[i].name, (*current->map)[i].descr);
                }
            }
            free((*current->map)[i].name);
            free((*current->map)[i].descr);
            if ((*current->map)[i].lasti)
                free((*current->map)[i].lasti);
            (*current->map)[i].lasti = 0;
            (*current->map)[i].descr = 0;
            (*current->map)[i].name = 0;
            (*current->map)[i].addr = 0xffffffff;
            // Yes, we might have some buffers in this space.
            {
                struct fenris_mem *m;
                while ((m = lookup_inrange(addr, (*current->map)[i].len)))
                    delete_mem(m->addr, 0);
            }
            (*current->map)[i].len = 0;
            return;
        }
}

#define SDCOND ((current->nest>=-1) && (!current->lcname[0]))

/******************************
 * Handle return from syscall *
 ******************************/

void ret_syscall(void)
{
    char buf[MAXFNAME];
    char b2[64];
    char b3[MAXFNAME];
    struct __old_kernel_stat os;
    struct __kernel_stat st;
    struct statfs sf;
    unsigned long a[6];
    int ah = 0;

    b3[0] = 0;
    buf[0] = 0;

    // FIXME: hardcoded?!? more than 300+ for i386
    if (current->idtop)
        sprintf(b2, "S %s:%s", lookup_fnct((*current->fnaddr)[current->idtop - 1], 0, 1),
                scnames[current->syscall & 0xff]);
    // FIXME: hardcoded?!? more than 300+ for i386
    else
        sprintf(b2, "S main:%s", scnames[current->syscall & 0xff]);

    switch (current->syscall) {

        case __NR_execve:
            if (r.rax < 0) {
                debug("%lld\n", r.rax);
            } else {
                debug("???\n");
                while (--current->nest >= -1) {
                    indent(0);
                    debug("...function never returned (program exited before).\n");
                    if (current->nest < 0 || current->isfnct[current->nest]) {
                        dump_memchg(0);
                        if (current->fntop)
                            current->fntop--;
                    }
                    if (T_dostep)
                        break_nestdown();
                }
                debug("+++ Process %d - image replaced %s+++\n", pid, T_execs ? "" : "(end of trace) ");
                remove_process();
                if (T_execs)
                    add_process(pid);
                else
                    ptrace(PTRACE_DETACH, pid, 0, 0);
            }
            break;

        case __NR_read:

            if (SDCOND) {
                indent(0);
                pdescr[0] = 0;

                debug("%sSYS read (%d, %x", in_libc ? "[L] " : "", Xf(current->pr.rbx), Xv(current->pr.rcx));

                get_string_from_child(current->pr.rcx, buf, MAXUNKNOWN);
                if (r.rax < 0) {
                    buf[0] = 0;
                } else {
                    buf[r.rax > MAXUNKNOWN ? MAXUNKNOWN : r.rax] = 0;
                }

                debug(" \"%s\"", buf);
                if (strlen(buf) == MAXUNKNOWN - 1)
                    debug("...");

                debug(", %lld) = %s\n", current->pr.rdx, toerror(r.rax));
                dump_pdescr(0);
                if (r.rax != -EFAULT) {
                    add_mem(current->pr.rcx, current->pr.rdx, 0, b2, 0);
                    modify_lasti(current->pr.rcx, b2, current->pr.rbx, 0, 0);
                }
            }
            break;

        case __NR_syslog:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;

                debug("%sSYS syslog (%lld, %x", in_libc ? "[L] " : "", current->pr.rbx, Xv(current->pr.rcx));

                buf[0] = 0;

                if (r.rax > 0) {
                    get_string_from_child(current->pr.rcx, buf, MAXUNKNOWN);
                    buf[r.rax > MAXUNKNOWN ? MAXUNKNOWN : r.rax] = 0;
                }

                debug(" \"%s\"", buf);
                if (strlen(buf) == MAXUNKNOWN - 1)
                    debug("...");

                debug(", %lld) = %s\n", current->pr.rdx, toerror(r.rax));

                dump_pdescr(0);

                if (r.rax != -EFAULT) {
                    if (r.rax > 0) {
                        add_mem(current->pr.rcx, current->pr.rdx, 0, b2, 0);
                        modify_lasti(current->pr.rcx, b2, current->pr.rbx, 0, 0);
                    }
                }

            }

            break;

        case __NR_readdir:

            if (SDCOND) {
                indent(0);
                pdescr[0] = 0;

                debug("%sSYS readdir (%d, %x", in_libc ? "[L] " : "", Xf(current->pr.rbx), Xv(current->pr.rcx));

                if (r.rax > 0) {
                    get_string_from_child(current->pr.rcx + 10, buf, sizeof(buf));
                    debug(" [\"%s\"]", buf);
                }

                debug(", %lld) = %s\n", current->pr.rdx, toerror(r.rax));

                dump_pdescr(0);

                if (r.rax != -EFAULT) {
                    add_mem(current->pr.rcx, sizeof(struct dirent), 0, b2, 0);
                    modify_lasti(current->pr.rcx, b2, current->pr.rbx, 0, 0);
                }

            }
            break;

        case __NR_sethostname:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;
                debug("%sSYS sethostname (%x", in_libc ? "[L] " : "", Xv(current->pr.rbx));

                if (!r.rax) {
                    get_string_from_child(current->pr.rbx, buf, current->pr.rcx + 3);
                    buf[current->pr.rcx] = 0;
                    debug(" \"%s\"", buf);
                }

                debug(") = %s\n", toerror(r.rax));
                dump_pdescr(0);

                if (!r.rax)
                    add_mem(current->pr.rbx, current->pr.rcx, 0, b2, 0);

            }

            break;

#ifdef __NR_gethostname
            // why the hell there's no such syscall on x86?
        case __NR_gethostname:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;
                debug("%sSYS gethostname (%x", in_libc ? "[L] " : "", Xv(current->pr.rbx));

                if (!r.rax) {
                    get_string_from_child(current->pr.rbx, buf, current->pr.rcx + 3);
                    buf[current->pr.rcx] = 0;
                    debug(" \"%s\"", buf);
                }

                debug(") = %s\n", toerror(r.rax));
                dump_pdescr(0);

                if (!r.rax) {
                    add_mem(current->pr.rbx, current->pr.rcx, 0, b2, 0);
                    modify_lasti(current->pr.rbx, b2, 0, 0, 0);
                }

            }

            break;
#endif /* __NR_gethostname */

        case __NR_write:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;

                debug("%sSYS write (%d, %x", in_libc ? "[L] " : "", Xf(current->pr.rbx), Xv(current->pr.rcx));

                get_string_from_child(current->pr.rcx, buf, MAXUNKNOWN);

                if (r.rax < 0) {
                    buf[0] = 0;
                } else {
                    if (r.rax <= MAXUNKNOWN) {
                        buf[r.rax] = 0;
                    }
                }

                debug(" \"%s\"", buf);

                if (strlen(buf) == MAXUNKNOWN - 1)
                    debug("...");

                debug(", %lld) = %s\n", current->pr.rdx, toerror(r.rax));
                dump_pdescr(0);
                if (r.rax != -EFAULT)
                    add_mem(current->pr.rcx, current->pr.rdx, 0, b2, 0);
            }
            break;

        case __NR_waitpid:

            if (SDCOND) {
                unsigned int q;
                indent(0);
                pdescr[0] = 0;
                debug("%sSYS waitpid (%lld, %x", in_libc ? "[L] " : "", current->pr.rbx, Xv(current->pr.rcx));
                if (r.rax >= 0) {
                    q = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);
                    if (WIFEXITED(q))
                        debug("[exit:%d]", WEXITSTATUS(q));
                    else if (WIFSIGNALED(q))
                        debug("[signal:%d]", WTERMSIG(q));
                    else if (WIFSTOPPED(q))
                        debug("[stop:%d]", WSTOPSIG(q));
                    else
                        debug("[0x%x]", q);
                } else
                    debug(" [?]");
                debug(", %llx) = %s\n", current->pr.rdx, toerror(r.rax));
                dump_pdescr(0);

                if (r.rax != -EFAULT) {
                    add_mem(current->pr.rcx, 4, 0, b2, 0);
                    modify_lasti(current->pr.rcx, b2, 0, 0, 0);
                }
            }
            break;

        case __NR_open:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                b3[0] = 0;

                if (current->pr.rcx & O_RDWR) {
                    current->pr.rcx -= O_RDWR;
                    strcat(b3, "O_RDWR");
                } else {
                    if (current->pr.rcx & O_WRONLY) {
                        current->pr.rcx -= O_WRONLY;
                        strcat(b3, "O_WRONLY");
                    } else {
                        strcat(b3, "O_RDONLY");
                    }
                }

                if (current->pr.rcx & O_CREAT) {
                    current->pr.rcx -= O_CREAT;
                    strcat(b3, " | O_CREAT");
                }
                if (current->pr.rcx & O_EXCL) {
                    current->pr.rcx -= O_EXCL;
                    strcat(b3, " | O_EXCL");
                }
                if (current->pr.rcx & O_APPEND) {
                    current->pr.rcx -= O_APPEND;
                    strcat(b3, " | O_APPEND");
                }
                if (current->pr.rcx & O_TRUNC) {
                    current->pr.rcx -= O_TRUNC;
                    strcat(b3, " | O_TRUNC");
                }
                if (current->pr.rcx & O_SYNC) {
                    current->pr.rcx -= O_SYNC;
                    strcat(b3, " | O_SYNC");
                }
                if (current->pr.rcx & O_NOCTTY) {
                    current->pr.rcx -= O_NOCTTY;
                    strcat(b3, " | O_NOCTTY");
                }
                if (current->pr.rcx & O_NONBLOCK) {
                    current->pr.rcx -= O_NONBLOCK;
                    strcat(b3, " | O_NONBLOCK");
                }
#ifdef O_NOFOLLOW
                if (current->pr.rcx & O_NOFOLLOW) {
                    current->pr.rcx -= O_NOFOLLOW;
                    strcat(b3, " | O_NOFOLLOW");
                }
#endif /* O_NOFOLLOW */

#ifdef O_DIRECTORY
                if (current->pr.rcx & O_DIRECTORY) {
                    current->pr.rcx -= O_DIRECTORY;
                    strcat(b3, " | O_DIRECTORY");
                }
#endif /* O_DIRECTORY */

#ifdef O_LARGEFILE
                if (current->pr.rcx & O_LARGEFILE) {
                    current->pr.rcx -= O_LARGEFILE;
                    strcat(b3, " | O_LARGEFILE");
                }
#endif /* O_LARGEFILE */

                if (current->pr.rcx) {
                    sprintf((char *)&b3[strlen(b3)], " | 0x%llx", current->pr.rcx);
                }

                pdescr[0] = 0;

                if (current->pr.rcx & O_CREAT)

                    debug("%sSYS open (%x \"%s\", %s, 0%llo) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), buf, b3, current->pr.rdx, toerror(r.rax));

                else

                    debug("%sSYS open (%x \"%s\", %s) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), buf, b3, toerror(r.rax));

                dump_pdescr(0);

            }

            if (r.rax >= 0)
                add_filedes(r.rax, buf, b2, 0);

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_access:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                b3[0] = 0;

                if (current->pr.rcx & R_OK) {
                    current->pr.rcx -= R_OK;
                    strcat(b3, "R_OK |");
                }
                if (current->pr.rcx & W_OK) {
                    current->pr.rcx -= W_OK;
                    strcat(b3, "W_OK |");
                }
                if (current->pr.rcx & X_OK) {
                    current->pr.rcx -= X_OK;
                    strcat(b3, "X_OK |");
                }
                if (current->pr.rcx & F_OK) {
                    current->pr.rcx -= F_OK;
                    strcat(b3, "F_OK |");
                }

                if (current->pr.rcx)
                    sprintf((char *)&b3[strlen(b3)], "0x%llx", current->pr.rcx);

                if (b3[strlen(b3) - 1] == '|')
                    b3[strlen(b3) - 2] = 0;

                pdescr[0] = 0;

                debug("%sSYS open (%x \"%s\", %s) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, b3, toerror(r.rax));

                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT)
            // add_mem(current->pr.rbx,strlen(buf)+1,0,b2,0);
            if (r.rax != EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_mknod:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                b3[0] = 0;

                if (S_ISCHR(current->pr.rcx))
                    strcpy(b3, "S_IFCHR");
                else if (S_ISBLK(current->pr.rcx))
                    strcpy(b3, "S_IFBLK");
                else if (S_ISFIFO(current->pr.rcx))
                    strcpy(b3, "S_IFIFO");
                else if (S_ISREG(current->pr.rcx))
                    strcpy(b3, "S_IFREG");
                else
                    sprintf(b3, "0x%llx", current->pr.rcx);

                pdescr[0] = 0;

                debug("%sSYS mknod (%x \"%s\", %s, 0%o) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, b3, (int)current->pr.rdx, toerror(r.rax));

                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != EFAULT)
            // add_mem(current->pr.rbx,strlen(buf)+1,0,b2,0);
            if (r.rax != EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;
        case __NR_oldstat:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_mem_from_child(current->pr.rcx, (char *)&os, sizeof(os));

            if (SDCOND) {

                indent(0);

                if (r.rax) {
                    strcpy(b3, "?");
                } else {
                    sprintf(b3, "%x:%x #%d 0%o %d.%d %dB", (int)os.st_dev, (int)os.st_ino,
                            (int)os.st_nlink, (int)os.st_mode, (int)os.st_uid, (int)os.st_gid, (int)os.st_size);
                }

                pdescr[0] = 0;

                debug("%sSYS oldstat (%x \"%s\", %x [%s]) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));

                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT) {
            if (r.rax != EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, sizeof(os), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, 0, 0, b3);
            }

            break;
        case __NR_statfs:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;

                debug("%sSYS statfs (%x \"%s\", %x [...]) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), toerror(r.rax));

                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT) {
            if (r.rax != EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, sizeof(sf), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, 0, 0, b3);
            }

            break;

        case __NR_oldlstat:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_mem_from_child(current->pr.rcx, (char *)&os, sizeof(os));

            if (SDCOND) {

                indent(0);

                if (r.rax)
                    strcpy(b3, "?");
                else
                    sprintf(b3, "%x:%x #%d 0%o %d.%d %dB", (int)os.st_dev, (int)os.st_ino,
                            (int)os.st_nlink, (int)os.st_mode, (int)os.st_uid, (int)os.st_gid, (int)os.st_size);

                pdescr[0] = 0;

                debug("%sSYS oldlstat (%x \"%s\", %x [%s]) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));

                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT) {
            if (r.rax != EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, sizeof(os), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, 0, 0, b3);
            }

            break;

        case __NR_stat:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_mem_from_child(current->pr.rcx, (char *)&st, sizeof(st));

            if (SDCOND) {

                indent(0);

                if (r.rax)
                    strcpy(b3, "?");
                else
                    sprintf(b3, "%x:%x #%d 0%o %d.%d %dB", (int)st.st_dev, (int)st.st_ino,
                            (int)st.st_nlink, (int)st.st_mode, (int)st.st_uid, (int)st.st_gid, (int)st.st_size);

                pdescr[0] = 0;
                debug("%sSYS stat (%x \"%s\", %x [%s]) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));
                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT) {
            if (r.rax != EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, sizeof(st), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, 0, 0, b3);
            }

            break;

        case __NR_lstat:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_mem_from_child(current->pr.rcx, (char *)&st, sizeof(st));

            if (SDCOND) {

                indent(0);

                if (r.rax)
                    strcpy(b3, "?");
                else
                    sprintf(b3, "%x:%x #%d 0%o %d.%d %dB", (int)st.st_dev, (int)st.st_ino,
                            (int)st.st_nlink, (int)st.st_mode, (int)st.st_uid, (int)st.st_gid, (int)st.st_size);

                pdescr[0] = 0;
                debug("%sSYS lstat (%x \"%s\", %x [%s]) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));
                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT) {
            if (r.rax != EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, sizeof(st), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, 0, 0, b3);
            }

            break;

        case __NR_fstat:

            get_mem_from_child(current->pr.rcx, (char *)&st, sizeof(st));

            if (SDCOND) {

                indent(0);

                if (r.rax)
                    strcpy(b3, "?");
                else
                    sprintf(b3, "%x:%x #%d 0%o %d.%d %dB", (int)st.st_dev, (int)st.st_ino,
                            (int)st.st_nlink, (int)st.st_mode, (int)st.st_uid, (int)st.st_gid, (int)st.st_size);

                pdescr[0] = 0;
                debug("%sSYS fstat (%d, %x [%s]) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), Xv(current->pr.rcx), b3, toerror(r.rax));

                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT) {
            if (r.rax != EFAULT) {
                add_mem(current->pr.rcx, sizeof(st), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, current->pr.rbx, 0, 0);
            }

            break;

        case __NR_fstatfs:

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS fstatfs (%d, %x [...]) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), Xv(current->pr.rcx), toerror(r.rax));

                dump_pdescr(0);

            }
            // FIXME: rax = unsigned long int, never <0
            // if (r.rax != -EFAULT) {
            if (r.rax != EFAULT) {
                add_mem(current->pr.rcx, sizeof(sf), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, current->pr.rbx, 0, 0);
            }

            break;

        case __NR_socketcall:  // How stupid

            if (current->nest >= 0)
                indent(0);

            get_mem_from_child(current->pr.rcx, (char *)&a[0], sizeof(a));
            if (((a[0] >> 16) == 0xffff) || ((a[6] >> 16) == 0xffff)) {

                if (current->nest >= 0)
                    debug("%sSYS socketcall_%d (0x%x <invalid>) = %s\n",
                          in_libc ? "[L] " : "", (int)current->pr.rbx, (int)current->pr.rcx, toerror(r.rax));

                break;
            }

            switch (current->pr.rbx) {
                case SYS_SOCKET:

                    {
                        struct protoent *p;
                        char *pro;

                        p = getprotobynumber(a[2]);
                        if (!p)
                            pro = "unknown";
                        else
                            pro = p->p_name;

                        switch (a[0]) {
                            case PF_UNIX:
                                strcpy(buf, "PF_UNIX");
                                break;
                            case PF_INET:
                                strcpy(buf, "PF_INET");
                                break;
                            case PF_INET6:
                                strcpy(buf, "PF_INET6");
                                break;
                            case PF_IPX:
                                strcpy(buf, "PF_IPX");
                                break;
                            case PF_NETLINK:
                                strcpy(buf, "PF_NETLINK");
                                break;
                            case PF_X25:
                                strcpy(buf, "PF_X25");
                                break;
                            case PF_AX25:
                                strcpy(buf, "PF_AX25");
                                break;
#ifdef PF_ATMPVC
                            case PF_ATMPVC:
                                strcpy(buf, "PF_ATMPVC");
                                break;
#endif /* PF_ATMPVC */
                            case PF_APPLETALK:
                                strcpy(buf, "PF_UPPLETALK");
                                break;
                            case PF_PACKET:
                                strcpy(buf, "PF_PACKET");
                                break;
                            default:
                                sprintf(buf, "0x%x", (int)a[0]);
                        }

                        switch (a[1]) {
                            case SOCK_STREAM:
                                strcpy(b3, "SOCK_STREAM");
                                break;
                            case SOCK_DGRAM:
                                strcpy(b3, "SOCK_DGRAM");
                                break;
                            case SOCK_SEQPACKET:
                                strcpy(b3, "SOCK_SEQPACKET");
                                break;
                            case SOCK_RAW:
                                strcpy(b3, "SOCK_RAW");
                                break;
                            case SOCK_RDM:
                                strcpy(b3, "SOCK_RDM");
                                break;
                            case SOCK_PACKET:
                                strcpy(b3, "SOCK_PACKET");
                                break;
                            default:
                                sprintf(b3, "0x%x", (int)a[0]);
                        }

                        if (current->nest >= 0)
                            debug("%sSYS socket (%s, %s, %d [%s]) = %s\n", in_libc ? "[L] " : "",
                                  buf, b3, (int)a[2], pro, toerror(r.rax));

                        // FIXME: rax = unsigned long int, never <0
                        // if (r.rax>=0) {
                        if (r.rax > 0) {
                            char b4[128];
                            sprintf(b4, "<new %s:%s:%s>", buf, b3, pro);
                            add_filedes(r.rax, b4, b2, a[0] == PF_UNIX ? -1 : 0);
                        }

                    }

                    break;

                case SYS_BIND: // <binded to port nn>, port -1 == unix sock

                    get_mem_from_child(a[1], b3, 108);

                    if (AS_USHORT(b3[0]) == PF_UNIX) {
                        sprintf(buf, " [local \"%s\"]", &b3[2]);
                    } else {
                        // FIXME: rax = unsigned long int, never <0
                        // if (r.rax == -EINVAL) strcpy(buf," [?]"); else
                        if (r.rax == EINVAL) {
                            strcpy(buf, " [?]");
                        } else {
                            sprintf(buf, " [%d.%d.%d.%d:%d]", b3[4], b3[5], b3[6], b3[7], b3[2] * 256 + b3[3]);
                        }
                    }

                    pdescr[0] = 0;

                    if (current->nest >= 0)
                        debug("%sSYS bind (%d, %x%s, %d) = %s\n", in_libc ? "[L] " : "",
                              Xf(a[0]), Xv(a[1]), buf, (int)a[2], toerror(r.rax));

                    dump_pdescr(0);

                    // FIXME: rax = unsigned long int, never <0
                    // if (r.rax != -EINVAL) add_mem(a[1],a[2],0,b2,0);
                    if (r.rax != EINVAL)
                        add_mem(a[1], a[2], 0, b2, 0);

                    // FIXME: rax = unsigned long int, never <0
                    // if (r.rax>=0) {
                    if (r.rax > 0) {
                        if (AS_USHORT(b3[0]) == PF_UNIX) {
                            sprintf(buf, "<on local %s>", &b3[2]);
                            modify_filedes(a[0], buf, -1);
                        } else {
                            sprintf(buf, "<on port %d>", b3[2] * 256 + b3[3]);
                            modify_filedes(a[0], buf, b3[2] * 256 + b3[3]);
                        }
                    }

                    break;

                case SYS_CONNECT:      // modify_filedes to "<conn to
                                        // host:port>", p -1

                    get_mem_from_child(a[1], b3, 108);

                    if (AS_USHORT(b3[0]) == PF_UNIX) {
                        sprintf(buf, " [local \"%s\"]", &b3[2]);
                    } else {
                        // FIXME: rax = unsigned long int, never <0
                        // if (r.rax == -EINVAL) strcpy(buf," [?]"); else
                        if (r.rax == EINVAL)
                            strcpy(buf, " [?]");
                        else
                            sprintf(buf, " [%d.%d.%d.%d:%d]", b3[4], b3[5], b3[6], b3[7], b3[2] * 256 + b3[3]);
                    }

                    pdescr[0] = 0;

                    if (current->nest >= 0)
                        debug("%sSYS connect (%d, %x%s, %d) = %s\n", in_libc ? "[L] " : "",
                              Xf(a[0]), Xv(a[1]), buf, (int)a[2], toerror(r.rax));

                    dump_pdescr(0);

                    // FIXME: rax = unsigned long int, never <0
                    // if ((r.rax != -EINVAL) && (a[2]>0))
                    // add_mem(a[1],a[2],0,b2,0);
                    if ((r.rax != EINVAL) && (a[2] > 0))
                        add_mem(a[1], a[2], 0, b2, 0);

                    // FIXME: rax = unsigned long int, never <0
                    // if (r.rax>=0) {
                    if (r.rax > 0) {
                        if (AS_USHORT(b3[0]) == PF_UNIX) {
                            sprintf(buf, "<to local %s>", &b3[2]);
                            modify_filedes(a[0], buf, -1);
                        } else {
                            sprintf(buf, "<to %d.%d.%d.%d:%d>", b3[4], b3[5], b3[6], b3[7], b3[2] * 256 + b3[3]);
                            modify_filedes(a[0], buf, 0);
                        }
                    }

                    break;

                case SYS_LISTEN:

                    pdescr[0] = 0;

                    if (current->nest >= 0)
                        debug("%sSYS listen (%d, %d) = %s\n", in_libc ? "[L] " : "",
                              Xf(a[0]), (int)a[1], toerror(r.rax));

                    dump_pdescr(0);

                    break;

                case SYS_ACCEPT:

                    if (a[1]) {
                        ah = ptrace(PTRACE_PEEKDATA, pid, a[2], 0);
                        get_mem_from_child(a[1], b3, 108);

                        if (AS_USHORT(b3[0]) == PF_UNIX) {
                            sprintf(buf, " [local \"%s\"]", &b3[2]);
                        } else {
                            // FIXME: rax = unsigned long int, never <0
                            // if (r.rax == -EINVAL) strcpy(buf," [?]"); else
                            if (r.rax == EINVAL)
                                strcpy(buf, " [?]");
                            else
                                sprintf(buf, " [%d.%d.%d.%d:%d]", b3[4], b3[5], b3[6], b3[7], b3[2] * 256 + b3[3]);
                        }
                    }

                    pdescr[0] = 0;

                    if (current->nest >= 0) {
                        if (!a[1]) {
                            debug("%sSYS accept (%d, %x, %x) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), Xv(a[2]), toerror(r.rax));
                            // FIXME: rax = unsigned long int, never <0
                            // } else if (r.rax>=0) {
                        } else if (r.rax > 0) {
                            debug("%sSYS accept (%d, %x%s, %x [%d]) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), buf, Xv(a[2]), ah, toerror(r.rax));
                        } else {
                            debug("%sSYS accept (%d, %x%s, %x) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), buf, Xv(a[2]), toerror(r.rax));
                        }
                    }

                    dump_pdescr(0);

                    // FIXME: rax = unsigned long int, never <0
                    // if (r.rax >= 0) {
                    if (r.rax > 0) {

                        if (a[1]) {
                            add_mem(a[1], ah, 0, b2, 0);
                            add_mem(a[2], 4, 0, b2, 0);
                            modify_lasti(a[1], b2, a[0], 0, 0);
                            modify_lasti(a[2], b2, a[0], 0, 0);

                            if (AS_USHORT(b3[0]) == PF_UNIX) {
                                sprintf(buf, "<from local %s>", &b3[2]);
                                add_filedes(r.rax, buf, b2, -1);
                            } else {
                                sprintf(buf, "<from %d.%d.%d.%d:%d>", b3[4], b3[5], b3[6], b3[7], b3[2] * 256 + b3[3]);
                                add_filedes(r.rax, buf, b2, 0);
                            }
                        } else {

                            if ((ah = get_filep(a[0])) < 0) {
                                sprintf(buf, "<from local>");
                                add_filedes(r.rax, buf, b2, -1);
                            } else {
                                sprintf(buf, "<from port %d>", ah);
                                add_filedes(r.rax, buf, b2, 0);
                            }

                        }

                    }

                    break;

                case SYS_GETSOCKNAME:

                    ah = ptrace(PTRACE_PEEKDATA, pid, a[2], 0);
                    get_mem_from_child(a[1], b3, 108);

                    if (AS_USHORT(b3[0]) == PF_UNIX) {
                        sprintf(buf, " [local \"%s\"]", &b3[2]);
                    } else {
                        // FIXME: rax = unsigned long int, never <0
                        // if (r.rax == -EINVAL) strcpy(buf," [?]"); else
                        if (r.rax == EINVAL)
                            strcpy(buf, " [?]");
                        else
                            sprintf(buf, " [%d.%d.%d.%d:%d]", b3[4], b3[5], b3[6], b3[7], b3[2] * 256 + b3[3]);
                    }

                    pdescr[0] = 0;

                    if (current->nest >= 0) {
                        if (!a[1]) {
                            debug("%sSYS getsockname (%d, %x, %x) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), Xv(a[2]), toerror(r.rax));
                            // FIXME: rax = unsigned long int, never <0
                            // } else if (r.rax>=0) {
                        } else if (r.rax > 0) {
                            debug("%sSYS getsockname (%d, %x%s, %x [%d]) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), buf, Xv(a[2]), ah, toerror(r.rax));
                        } else {
                            debug("%sSYS getsockname (%d, %x%s, %x) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), buf, Xv(a[2]), toerror(r.rax));
                        }
                    }

                    dump_pdescr(0);

                    // FIXME: rax = unsigned long int, never <0
                    // if (r.rax >= 0) {
                    if (r.rax > 0) {

                        add_mem(a[1], ah, 0, b2, 0);
                        add_mem(a[2], 4, 0, b2, 0);
                        modify_lasti(a[1], b2, a[0], 0, 0);
                        modify_lasti(a[2], b2, a[0], 0, 0);

                    }

                    break;

                case SYS_GETPEERNAME:

                    ah = ptrace(PTRACE_PEEKDATA, pid, a[2], 0);
                    get_mem_from_child(a[1], b3, 108);

                    if (AS_USHORT(b3[0]) == PF_UNIX) {
                        sprintf(buf, " [local \"%s\"]", &b3[2]);
                    } else {
                        // FIXME: rax = unsigned long int, never <0
                        // if (r.rax == -EINVAL) strcpy(buf," [?]"); else
                        if (r.rax == EINVAL)
                            strcpy(buf, " [?]");
                        else
                            sprintf(buf, " [%d.%d.%d.%d:%d]", b3[4], b3[5], b3[6], b3[7], b3[2] * 256 + b3[3]);
                    }

                    pdescr[0] = 0;

                    if (current->nest >= 0) {
                        if (!a[1]) {
                            debug("%sSYS getpeername (%d, %x, %x) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), Xv(a[2]), toerror(r.rax));
                            // FIXME: rax = unsigned long int, never <0
                            // } else if (r.rax>=0) {
                        } else if (r.rax > 0) {
                            debug("%sSYS getpeername (%d, %x%s, %x [%d]) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), buf, Xv(a[2]), ah, toerror(r.rax));
                        } else {
                            debug("%sSYS getpeername (%d, %x%s, %x) = %s\n", in_libc ? "[L] " : "",
                                  Xf(a[0]), Xv(a[1]), buf, Xv(a[2]), toerror(r.rax));
                        }
                    }

                    dump_pdescr(0);

                    // FIXME: rax = unsigned long int, never <0
                    // if (r.rax >= 0) {
                    if (r.rax > 0) {

                        add_mem(a[1], ah, 0, b2, 0);
                        add_mem(a[2], 4, 0, b2, 0);
                        modify_lasti(a[1], b2, a[0], 0, 0);
                        modify_lasti(a[2], b2, a[0], 0, 0);

                    }

                    break;

                case SYS_SEND:

                    if (SDCOND) {
                        indent(0);
                        pdescr[0] = 0;

                        debug("%sSYS send (%d, %x", in_libc ? "[L] " : "", Xf(a[0]), Xv(a[1]));

                        get_string_from_child(a[1], buf, MAXUNKNOWN);
                        // FIXME: rax = unsigned long int, never <0
                        // if (r.rax<0) {
                        // buf[0]=0;
                        // } else {
                        buf[r.rax > MAXUNKNOWN ? MAXUNKNOWN : r.rax] = 0;
                        // }

                        debug(" \"%s\"", buf);
                        if (strlen(buf) == MAXUNKNOWN - 1)
                            debug("...");

                        debug(", %d, 0x%x) = %s\n", (int)a[2], (int)a[3], toerror(r.rax));
                        dump_pdescr(0);
                        // FIXME: rax = unsigned long int, never <0
                        // if (r.rax != -EFAULT) {
                        if (r.rax != EFAULT) {
                            add_mem(a[1], a[2], 0, b2, 0);
                        }
                    }
                    break;

                case SYS_RECV:

                    if (SDCOND) {
                        indent(0);
                        pdescr[0] = 0;

                        debug("%sSYS recv (%d, %x", in_libc ? "[L] " : "", Xf(a[0]), Xv(a[1]));

                        get_string_from_child(a[1], buf, MAXUNKNOWN);
                        if (r.rax < 0)
                            buf[0] = 0;
                        else
                            buf[r.rax > MAXUNKNOWN ? MAXUNKNOWN : r.rax] = 0;

                        debug(" \"%s\"", buf);
                        if (strlen(buf) == MAXUNKNOWN - 1)
                            debug("...");

                        debug(", %d, 0x%x) = %s\n", (int)a[2], (int)a[3], toerror(r.rax));
                        dump_pdescr(0);
                        if (r.rax != -EFAULT) {
                            add_mem(a[1], a[2], 0, b2, 0);
                            modify_lasti(a[1], b2, a[0], 0, 0);
                        }
                    }
                    break;

                case SYS_SOCKETPAIR:

                    {
                        struct protoent *p;
                        char *pro;

                        p = getprotobynumber(a[2]);
                        if (!p)
                            pro = "unknown";
                        else
                            pro = p->p_name;

                        switch (a[0]) {
                            case PF_UNIX:
                                strcpy(buf, "PF_UNIX");
                                break;
                            case PF_INET:
                                strcpy(buf, "PF_INET");
                                break;
                            case PF_INET6:
                                strcpy(buf, "PF_INET6");
                                break;
                            case PF_IPX:
                                strcpy(buf, "PF_IPX");
                                break;
                            case PF_NETLINK:
                                strcpy(buf, "PF_NETLINK");
                                break;
                            case PF_X25:
                                strcpy(buf, "PF_X25");
                                break;
                            case PF_AX25:
                                strcpy(buf, "PF_AX25");
                                break;
#ifdef PF_ATMPVC
                            case PF_ATMPVC:
                                strcpy(buf, "PF_ATMPVC");
                                break;
#endif /* PF_ATMPVC */
                            case PF_APPLETALK:
                                strcpy(buf, "PF_UPPLETALK");
                                break;
                            case PF_PACKET:
                                strcpy(buf, "PF_PACKET");
                                break;
                            default:
                                sprintf(buf, "0x%x", (int)a[0]);
                        }

                        switch (a[1]) {
                            case SOCK_STREAM:
                                strcpy(b3, "SOCK_STREAM");
                                break;
                            case SOCK_DGRAM:
                                strcpy(b3, "SOCK_DGRAM");
                                break;
                            case SOCK_SEQPACKET:
                                strcpy(b3, "SOCK_SEQPACKET");
                                break;
                            case SOCK_RAW:
                                strcpy(b3, "SOCK_RAW");
                                break;
                            case SOCK_RDM:
                                strcpy(b3, "SOCK_RDM");
                                break;
                            case SOCK_PACKET:
                                strcpy(b3, "SOCK_PACKET");
                                break;
                            default:
                                sprintf(b3, "0x%x", (int)a[0]);
                        }

                        pdescr[0] = 0;

                        if (r.rax >= 0) {
                            char b4[128];
                            int x, y;

                            x = ptrace(PTRACE_PEEKDATA, pid, a[3], 0);
                            y = ptrace(PTRACE_PEEKDATA, pid, a[3] + 4, 0);

                            if (current->nest >= 0)
                                debug("%sSYS socketpair (%s, %s, %d [%s], %x [%d %d]) = %s\n",
                                      in_libc ? "[L] " : "", buf, b3, (int)a[2], pro, Xv(a[3]), x, y, toerror(r.rax));

                            sprintf(b4, "<new %s:%s:%s>", buf, b3, pro);
                            add_filedes(x, b4, b2, a[0] == PF_UNIX ? -1 : 0);
                            add_filedes(y, b4, b2, a[0] == PF_UNIX ? -1 : 0);

                        } else {

                            if (current->nest >= 0)
                                debug("%sSYS socketpair (%s, %s, %d [%s], %x) = %s\n",
                                      in_libc ? "[L] " : "", buf, b3, (int)a[2], pro, Xv(a[3]), toerror(r.rax));

                        }

                        dump_pdescr(0);

                        if (r.rax != -EFAULT) {
                            add_mem(a[3], 8, 0, b2, 0);
                            if (r.rax >= 0)
                                modify_lasti(a[3], b2, 0, 0, 0);
                        }

                    }

                    break;

                case SYS_SHUTDOWN:     // modify to: <unplugged sock>

                    pdescr[0] = 0;
                    if (current->nest >= 0)
                        debug("%sSYS shutdown (%d, %d) = %s\n",
                              in_libc ? "[L] " : "", Xf(a[0]), (int)a[1], toerror(r.rax));
                    dump_pdescr(0);

                    if (r.rax >= 0)
                        modify_filedes(a[0], "<unplugged>", 0);

                    break;

                case SYS_SENDTO:
                case SYS_RECVFROM:
                case SYS_SETSOCKOPT:
                case SYS_GETSOCKOPT:
                case SYS_SENDMSG:
                case SYS_RECVMSG:

                default:

                    if (current->nest >= 0) {
                        debug("%sSYS socketcall_%d ??? (", in_libc ? "[L] " : "", (int)current->pr.rbx);
                        pdescr[0] = 0;
                        display_value(a[0], b2);
                        debug(", ");
                        display_value(a[1], b2);
                        debug(", ");
                        display_value(a[2], b2);
                        debug(", ");
                        display_value(a[3], b2);
                        debug(", ");
                        display_value(a[4], b2);
                        debug(", ");
                        display_value(a[5], b2);
                        debug(") = ");
                        display_value(r.rax, b2);
                        debug("\n");
                        dump_pdescr(0);
                    }

            }

            break;

        case __NR_oldfstat:

            get_mem_from_child(current->pr.rcx, (char *)&os, sizeof(os));

            if (SDCOND) {

                indent(0);

                if (r.rax)
                    strcpy(b3, "?");
                else
                    sprintf(b3, "%x:%x #%d 0%o %d.%d %dB", (int)os.st_dev, (int)os.st_ino,
                            (int)os.st_nlink, (int)os.st_mode, (int)os.st_uid, (int)os.st_gid, (int)os.st_size);

                pdescr[0] = 0;
                debug("%sSYS oldfstat (%d, %x [%s]) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), Xv(current->pr.rcx), b3, toerror(r.rax));

                dump_pdescr(0);

            }

            if (r.rax != -EFAULT) {
                add_mem(current->pr.rcx, sizeof(st), 0, b2, 0);
                modify_lasti(current->pr.rcx, b2, current->pr.rcx, 0, 0);
            }

            break;

        case __NR_chmod:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS chmod (%x \"%s\", 0%o) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rdx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_creat:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS creat (%x \"%s\", 0%o) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax >= 0)
                add_filedes(r.rax, buf, b2, 0);
            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_link:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_string_from_child(current->pr.rcx, b3, sizeof(b3));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS link (%x \"%s\", %x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, strlen(b3) + 1, 0, b2, 0);
            }

            break;

        case __NR_symlink:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_string_from_child(current->pr.rcx, b3, sizeof(b3));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS symlink (%x \"%s\", %x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, strlen(b3) + 1, 0, b2, 0);
            }

            break;

        case __NR_rename:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_string_from_child(current->pr.rcx, b3, sizeof(b3));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS rename (%x \"%s\", %x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, strlen(b3) + 1, 0, b2, 0);
            }

            break;

        case __NR_mount:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));
            get_string_from_child(current->pr.rcx, b3, sizeof(b3));

            if (SDCOND) {

                indent(0);

                // absolutely no purpose in parsing params.
                pdescr[0] = 0;
                debug("%sSYS mount (%x \"%s\", %x \"%s\", [...]) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT) {
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);
                add_mem(current->pr.rcx, strlen(b3) + 1, 0, b2, 0);
            }

            break;

        case __NR_unlink:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS unlink (%x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_umount:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS umount (%x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_umount2:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS umount2 (%x \"%s\", %d) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_chdir:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS chdir (%x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_uselib:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS uselib (%x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_readlink:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;

                if (r.rax >= 0) {
                    int m = r.rax;
                    if (m >= (int)sizeof(b3))
                        m = sizeof(b3) - 1;
                    get_string_from_child(current->pr.rcx, b3, m);
                    debug("%sSYS readlink (%x \"%s\", %x \"%s\", %d) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), buf, Xv(current->pr.rcx), b3, (int)current->pr.rdx, toerror(r.rax));

                    add_mem(current->pr.rcx, current->pr.rdx, 0, b2, 0);
                    modify_lasti(current->pr.rcx, b2, 0, 0, buf);

                } else {

                    debug("%sSYS readlink (%x \"%s\", %x, %d) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), buf, Xv(current->pr.rcx), (int)current->pr.rdx, toerror(r.rax));

                }

                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_swapon:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS swapon (%x \"%s\", 0x%x) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_swapoff:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS swapoff (%x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_chroot:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS chroot (%x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_mkdir:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS mkdir (%x \"%s\", 0%o) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_rmdir:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS rmdir (%x \"%s\") = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_acct:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS acct (%x \"%s\") = %s\n", in_libc ? "[L] " : "", Xv(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax >= 0)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_fchdir:

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;

                debug("%sSYS fchdir (%d) = %s\n", in_libc ? "[L] " : "", Xf(current->pr.rbx), toerror(r.rax));

                dump_pdescr(0);

            }

            break;

        case __NR_lseek:

            if (SDCOND) {

                indent(0);

                if (current->pr.rdx == SEEK_SET)
                    strcpy(buf, "SEEK_SET");
                else if (current->pr.rdx == SEEK_CUR)
                    strcpy(buf, "SEEK_CUR");
                else if (current->pr.rdx == SEEK_END)
                    strcpy(buf, "SEEK_END");
                else
                    sprintf(buf, "%d", (int)current->pr.rdx);

                pdescr[0] = 0;

                debug("%sSYS lseek (%d, %d, %s) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), (int)current->pr.rcx, buf, toerror(r.rax));

                dump_pdescr(0);
            }

            break;

        case __NR_lchown:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS lchown (%x \"%s\", %d, %d) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rcx, (int)current->pr.rdx, toerror(r.rax));
                dump_pdescr(0);
            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_fchown:

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;

                debug("%sSYS fchown (%d, %d, %d) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), (int)current->pr.rcx, (int)current->pr.rdx, toerror(r.rax));

                dump_pdescr(0);

            }

            break;

        case __NR_fchmod:

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;

                debug("%sSYS fchmod (%d, 0%o) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), (int)current->pr.rcx, toerror(r.rax));

                dump_pdescr(0);

            }

            break;

        case __NR_chown:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS chown (%x \"%s\", %d, %d) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rcx, (int)current->pr.rdx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_truncate:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS truncate (%x \"%s\", %d) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), buf, (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_ftruncate:

            get_string_from_child(current->pr.rbx, buf, sizeof(buf));

            if (SDCOND) {

                indent(0);

                pdescr[0] = 0;
                debug("%sSYS ftruncate (%d, %d) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);

            }

            if (r.rax != -EFAULT)
                add_mem(current->pr.rbx, strlen(buf) + 1, 0, b2, 0);

            break;

        case __NR_time:

            if (SDCOND) {
                indent(0);

                if (r.rax > 0) {
                    strcpy(buf, ctime((time_t *) & r.rax));
                    if (buf[strlen(buf) - 1] == '\n')
                        buf[strlen(buf) - 1] = 0;

                    pdescr[0] = 0;
                    debug("%sSYS time (0x%x) = %s [%s]\n", in_libc ? "[L] " : "",
                          current->pr.rbx ? Xv(current->pr.rbx) : 0, toerror(r.rax), buf);
                    dump_pdescr(0);

                } else {
                    debug("%sSYS time (0x%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
                }

            }

            if ((r.rax > 0) && (current->pr.rbx > 0)) {
                add_mem(current->pr.rbx, 4, 0, b2, 0);
                modify_lasti(current->pr.rbx, b2, 0, 0, 0);
            }

            break;

        case __NR_utime:

            get_string_from_child(current->pr.rbx, b3, sizeof(b3));

            if (SDCOND) {
                indent(0);

                if (!r.rax) {
                    int a1, m1;
                    if (current->pr.rcx) {
                        a1 = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);
                        m1 = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx + 4, 0);
                        sprintf(buf, "[A: %s", ctime((void *)&a1));
                        if (buf[strlen(buf) - 1] == '\n')
                            buf[strlen(buf) - 1] = 0;
                        sprintf(&buf[strlen(buf)], "] [M: %s", ctime((void *)&m1));
                        if (buf[strlen(buf) - 1] == '\n')
                            buf[strlen(buf) - 1] = 0;
                    } else
                        strcpy(buf, "[A: now] [M: now");

                    pdescr[0] = 0;
                    debug("%sSYS utime (%x \"%s\", 0x%x %s]) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), b3, current->pr.rcx ? Xv(current->pr.rcx) : 0, buf, toerror(r.rax));
                    dump_pdescr(0);

                } else {
                    pdescr[0] = 0;
                    debug("%sSYS utime (%x \"%s\", 0x%x) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), b3, (int)current->pr.rcx, toerror(r.rax));
                    dump_pdescr(0);
                }

            }

            if (!r.rax) {
                add_mem(current->pr.rbx, strlen(b3) + 1, 0, b2, 0);
                if (current->pr.rcx) {
                    add_mem(current->pr.rcx, 8, 0, b2, 0);
                    modify_lasti(current->pr.rcx, b2, 0, 0, b3);
                }
            }

            break;

        case __NR_stime:

            if (SDCOND) {
                indent(0);

                if (!r.rax) {
                    time_t q;
                    q = (int)ptrace(PTRACE_PEEKDATA, pid, (int)current->pr.rbx, 0);
                    strcpy(buf, ctime(&q));
                    if (buf[strlen(buf) - 1] == '\n')
                        buf[strlen(buf) - 1] = 0;
                    pdescr[0] = 0;
                    debug("%sSYS stime (0x%x) = %s [%s]\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), toerror(r.rax), buf);
                    dump_pdescr(0);
                } else {
                    debug("%sSYS stime (0x%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
                }

            }

            if (!r.rax)
                add_mem(current->pr.rbx, 4, 0, b2, 0);

            break;

        case __NR_close:

            if (SDCOND) {
                indent(0);
                pdescr[0] = 0;
                debug("%sSYS close (%d) = %s\n", in_libc ? "[L] " : "", Xf(current->pr.rbx), toerror(r.rax));
                dump_pdescr(0);
            }

            if (r.rax >= 0)
                remove_filedes(current->pr.rbx);

            break;

        case __NR_fsync:

            if (SDCOND) {
                indent(0);
                pdescr[0] = 0;
                debug("%sSYS fsync (%d) = %s\n", in_libc ? "[L] " : "", Xf(current->pr.rbx), toerror(r.rax));
                dump_pdescr(0);
            }

            break;

        case __NR_fdatasync:

            if (SDCOND) {
                indent(0);
                pdescr[0] = 0;
                debug("%sSYS fdatasync (%d) = %s\n", in_libc ? "[L] " : "", Xf(current->pr.rbx), toerror(r.rax));
                dump_pdescr(0);
            }

            break;

        case __NR_rt_sigreturn:
        case __NR_sigreturn:

            if (SDCOND) {
                indent(0);
                debug("%sSYS sigreturn () = <void>\n", in_libc ? "[L] " : "");
            }

            break;

        case __NR_ioctl:

            if (SDCOND) {
                unsigned int i;
                indent(0);

                sprintf(buf, "%x", (int)current->pr.rcx);
                for (i = 0; i < sizeof(ioctls) / sizeof(struct ioctl_data); i++)
                    if (current->pr.rcx == ioctls[i].n) {
                        strcpy(buf, ioctls[i].name);
                        break;
                    }

                pdescr[0] = 0;

                debug("%sSYS ioctl (%d, %s, 0x%x) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), buf, (int)current->pr.rdx, toerror(r.rax));

                dump_pdescr(0);

            }

            break;

        case __NR_fcntl:

            if (SDCOND) {
                pdescr[0] = 0;
                Xf(current->pr.rbx);
            }

            switch (current->pr.rcx) {

                case F_DUPFD:

                    if (SDCOND) {
                        pdescr[0] = 0;
                        debug("%sSYS fcntl (%d, F_DUPFD, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                        dump_pdescr(0);
                    }
                    if (r.rax >= 0)
                        dup_filedes(current->pr.rbx, r.rax, b2);
                    break;

                case F_GETFD:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_GETFD, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_SETFD:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_SETFD, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_GETOWN:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_GETOWN, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_SETOWN:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_SETOWN, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

#ifdef F_SETSIG
                case F_GETSIG:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_GETSIG, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_SETSIG:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_SETSIG, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;
#endif /* F_SETSIG */

                case F_GETFL:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_GETFL, 0x%x) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_SETFL:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_SETFL, 0x%x) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_GETLK:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_GETLK, 0x%x) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_SETLK:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_SETLK, 0x%x) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                case F_SETLKW:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, F_SETLKW, 0x%x) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
                    break;

                default:

                    if (SDCOND)
                        debug("%sSYS fcntl (%d, %x, %d) = %s\n", in_libc ? "[L] " : "",
                              (int)current->pr.rbx, (int)current->pr.rcx, (int)current->pr.rdx, toerror(r.rax));

            }

            if (SDCOND)
                dump_pdescr(0);

            break;

        case __NR_dup2:

            if (SDCOND) {
                indent(0);
                pdescr[0] = 0;
                debug("%sSYS dup2 (%d, %d) = %s\n", in_libc ? "[L] " : "",
                      Xf(current->pr.rbx), (int)current->pr.rcx, toerror(r.rax));

                dump_pdescr(0);

            }

            if (r.rax >= 0)
                dup_filedes(current->pr.rbx, current->pr.rcx, b2);

            break;

        case __NR_pipe:

            if (r.rax) {

                if (SDCOND) {
                    indent(0);
                    debug("%sSYS pipe (%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
                }

            } else {
                int re, wr;
                re = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx, 0);
                wr = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4, 0);

                if (SDCOND) {
                    indent(0);
                    pdescr[0] = 0;
                    debug("%sSYS pipe (%x [r%d w%d]) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), re, wr, toerror(r.rax));
                    dump_pdescr(0);
                }

                add_filedes(re, "<pipe:read>", b2, 0);
                add_filedes(wr, "<pipe:write>", b2, 0);
                add_mem(current->pr.rbx, 8, 0, b2, 0);

            }

            break;

        case __NR_times:

            if ((r.rax < 0) || (!current->pr.rbx)) {

                if (SDCOND) {
                    indent(0);
                    debug("%sSYS times (%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
                }

            } else {

                if (SDCOND) {
                    int u, s, cu, cs;
                    indent(0);
                    u = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx, 0);
                    s = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4, 0);
                    cu = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 8, 0);
                    cs = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 12, 0);
                    debug("%sSYS times (%x [u%d s%d cu%d cs%d]) = %s\n", in_libc ? "[L] " : "",
                          (int)(current->pr.rbx), u, s, cu, cs, toerror(r.rax));
                }

                add_mem(current->pr.rbx, 16, 0, b2, 0);

            }

            break;

        case __NR_dup:

            if (SDCOND) {
                indent(0);
                pdescr[0] = 0;
                debug("%sSYS dup (%d) = %s\n", in_libc ? "[L] " : "", Xf(current->pr.rbx), toerror(r.rax));
                dump_pdescr(0);
            }

            if (r.rax >= 0)
                dup_filedes(current->pr.rbx, r.rax, b2);

            break;

        case __NR_ptrace:

            if (SDCOND) {
                indent(0);

                switch ((int)current->pr.rbx) {
                    case PTRACE_TRACEME:
                        strcpy(buf, "PTRACE_TRACEME");
                        break;
                    case PTRACE_PEEKTEXT:
                        strcpy(buf, "PTRACE_PEEKTEXT");
                        break;
                    case PTRACE_PEEKDATA:
                        strcpy(buf, "PTRACE_PEEKDATA");
                        break;
                    case PTRACE_PEEKUSER:
                        strcpy(buf, "PTRACE_PEEKUSR");
                        break;
                    case PTRACE_POKETEXT:
                        strcpy(buf, "PTRACE_POKETEXT");
                        break;
                    case PTRACE_POKEDATA:
                        strcpy(buf, "PTRACE_POKEDATA");
                        break;
                    case PTRACE_POKEUSER:
                        strcpy(buf, "PTRACE_POKEUSR");
                        break;
                    case PTRACE_CONT:
                        strcpy(buf, "PTRACE_CONT");
                        break;
                    case PTRACE_KILL:
                        strcpy(buf, "PTRACE_KILL");
                        break;
                    case PTRACE_SINGLESTEP:
                        strcpy(buf, "PTRACE_SINGLESTEP");
                        break;
                    case PTRACE_ATTACH:
                        strcpy(buf, "PTRACE_ATTACH");
                        break;
                    case PTRACE_DETACH:
                        strcpy(buf, "PTRACE_DETACH");
                        break;
                    case PTRACE_SYSCALL:
                        strcpy(buf, "PTRACE_SYSCALL");
                        break;
                    case PTRACE_GETREGS:
                        strcpy(buf, "PTRACE_GETREGS");
                        break;
                    case PTRACE_SETREGS:
                        strcpy(buf, "PTRACE_SETREGS");
                        break;
                    case PTRACE_GETFPREGS:
                        strcpy(buf, "PTRACE_GETFPREGS");
                        break;
                    case PTRACE_SETFPREGS:
                        strcpy(buf, "PTRACE_SETFPREGS");
                        break;
#ifdef PTRACE_GETFPXREGS
                    case PTRACE_GETFPXREGS:
                        strcpy(buf, "PTRACE_GETFPXREGS");
                        break;
                    case PTRACE_SETFPXREGS:
                        strcpy(buf, "PTRACE_SETFPXREGS");
                        break;
#endif /* PTRACE_GETFPXREGS */
                    default:
                        sprintf(buf, "%d", (int)current->pr.rbx);
                }

                debug("%sSYS ptrace (%s, %d, 0x%x, 0x%x) = %s\n", in_libc ? "[L] " : "",
                      buf, (int)current->pr.rcx, (int)current->pr.rdx, (int)current->pr.rsi, toerror(r.rax));
            }

            break;

        case __NR_getrlimit:

            if (SDCOND) {
                indent(0);

                switch ((int)current->pr.rbx) {
                    case RLIMIT_CPU:
                        strcpy(buf, "RLIMIT_CPU");
                        break;
                    case RLIMIT_FSIZE:
                        strcpy(buf, "RLIMIT_FSIZE");
                        break;
                    case RLIMIT_DATA:
                        strcpy(buf, "RLIMIT_DATA");
                        break;
                    case RLIMIT_STACK:
                        strcpy(buf, "RLIMIT_STACK");
                        break;
                    case RLIMIT_CORE:
                        strcpy(buf, "RLIMIT_CORE");
                        break;
                    case RLIMIT_RSS:
                        strcpy(buf, "RLIMIT_RSS");
                        break;
                    case RLIMIT_NPROC:
                        strcpy(buf, "RLIMIT_NPROC");
                        break;
                    case RLIMIT_NOFILE:
                        strcpy(buf, "RLIMIT_NOFILE");
                        break;
                    case RLIMIT_MEMLOCK:
                        strcpy(buf, "RLIMIT_MEMLOCK");
                        break;
                    case RLIMIT_AS:
                        strcpy(buf, "RLIMIT_AS");
                        break;
                    default:
                        sprintf(buf, "%d", (int)current->pr.rbx);
                }

                pdescr[0] = 0;

                if (r.rax) {
                    debug("%sSYS getrlimit (%s, %x) = %s\n", in_libc ? "[L] " : "",
                          buf, Xv(current->pr.rcx), toerror(r.rax));
                } else {
                    unsigned int cur, max;
                    cur = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);
                    max = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx + 4, 0);
                    debug("%sSYS getrlimit (%s, %x [cur:%d max:%d]) = %s\n", in_libc ? "[L] " : "",
                          buf, Xv(current->pr.rcx), cur, max, toerror(r.rax));
                    add_mem(current->pr.rcx, 8, 0, b2, 0);
                    modify_lasti(current->pr.rcx, b2, 0, 0, 0);
                }

                dump_pdescr(0);

            }

            break;

        case __NR_gettimeofday:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;

                if (r.rax) {
                    debug("%sSYS gettimeofday (%x, %x) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), Xv(current->pr.rcx), toerror(r.rax));
                } else {
                    unsigned int sec, usec;
                    unsigned int mwest;
                    sec = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx, 0);
                    usec = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4, 0);
                    mwest = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);
                    debug("%sSYS gettimeofday (%x [%ds %dms], %x [mw:%d]) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), sec, usec, Xv(current->pr.rcx), mwest, toerror(r.rax));
                    add_mem(current->pr.rbx, 8, 0, b2, 0);
                    add_mem(current->pr.rcx, 8, 0, b2, 0);
                    modify_lasti(current->pr.rbx, b2, 0, 0, 0);
                    modify_lasti(current->pr.rcx, b2, 0, 0, 0);
                }

                dump_pdescr(0);

            }

            break;

        case __NR_settimeofday:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;

                if (r.rax) {
                    debug("%sSYS settimeofday (%x, %x) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), Xv(current->pr.rcx), toerror(r.rax));
                } else {
                    unsigned int sec, usec;
                    unsigned int mwest;
                    sec = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx, 0);
                    usec = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4, 0);
                    mwest = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);
                    debug("%sSYS settimeofday (%x [%ds %dms], %x [mw:%d]) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), sec, usec, Xv(current->pr.rcx), mwest, toerror(r.rax));
                    add_mem(current->pr.rbx, 8, 0, b2, 0);
                    add_mem(current->pr.rcx, 8, 0, b2, 0);
                }

                dump_pdescr(0);

            }

            break;

        case __NR_getrusage:

            if (SDCOND) {
                indent(0);

                switch ((int)current->pr.rbx) {
                    case RUSAGE_SELF:
                        strcpy(buf, "RUSAGE_SELF");
                        break;
                    case RUSAGE_CHILDREN:
                        strcpy(buf, "RUSAGE_CHILDREN");
                        break;
                    default:
                        sprintf(buf, "%d", (int)current->pr.rbx);
                }

                pdescr[0] = 0;

                debug("%sSYS getrusage (%s, %x) = %s\n", in_libc ? "[L] " : "",
                      buf, Xv(current->pr.rcx), toerror(r.rax));

                if (!r.rax) {
                    add_mem(current->pr.rcx, sizeof(struct rusage), 0, b2, 0);
                    modify_lasti(current->pr.rcx, b2, 0, 0, 0);
                }

                dump_pdescr(0);

            }

            break;

        case __NR_setrlimit:

            if (SDCOND) {
                indent(0);

                switch ((int)current->pr.rbx) {
                    case RLIMIT_CPU:
                        strcpy(buf, "RLIMIT_CPU");
                        break;
                    case RLIMIT_FSIZE:
                        strcpy(buf, "RLIMIT_FSIZE");
                        break;
                    case RLIMIT_DATA:
                        strcpy(buf, "RLIMIT_DATA");
                        break;
                    case RLIMIT_STACK:
                        strcpy(buf, "RLIMIT_STACK");
                        break;
                    case RLIMIT_CORE:
                        strcpy(buf, "RLIMIT_CORE");
                        break;
                    case RLIMIT_RSS:
                        strcpy(buf, "RLIMIT_RSS");
                        break;
                    case RLIMIT_NPROC:
                        strcpy(buf, "RLIMIT_NPROC");
                        break;
                    case RLIMIT_NOFILE:
                        strcpy(buf, "RLIMIT_NOFILE");
                        break;
                    case RLIMIT_MEMLOCK:
                        strcpy(buf, "RLIMIT_MEMLOCK");
                        break;
                    case RLIMIT_AS:
                        strcpy(buf, "RLIMIT_AS");
                        break;
                    default:
                        sprintf(buf, "%d", (int)current->pr.rbx);
                }

                pdescr[0] = 0;

                if (r.rax) {
                    debug("%sSYS setrlimit (%s, %x) = %s\n", in_libc ? "[L] " : "",
                          buf, Xv(current->pr.rcx), toerror(r.rax));
                } else {
                    unsigned int cur, max;
                    cur = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);
                    max = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx + 4, 0);
                    debug("%sSYS setrlimit (%s, %x [cur:%d max:%d]) = %s\n", in_libc ? "[L] " : "",
                          buf, Xv(current->pr.rcx), cur, max, toerror(r.rax));
                    add_mem(current->pr.rcx, 8, 0, b2, 0);
                }

                dump_pdescr(0);

            }

            break;

        case __NR_setuid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS setuid (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_reboot:

            if (SDCOND) {
                indent(0);
                debug("%sSYS reboot (0x%x, 0x%x, 0x%x, 0x%x) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx,
                      (int)current->pr.rdx, (int)current->pr.rsi, toerror(r.rax));
            }

            break;

        case __NR_setreuid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS setreuid (%d, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
            }

            break;

        case __NR_setregid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS setregid (%d, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rdx, toerror(r.rax));
            }

            break;

        case __NR_setsid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS setsid () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_umask:

            if (SDCOND) {
                indent(0);
                debug("%sSYS umask (0%o) = 0%o\n", in_libc ? "[L] " : "", (int)current->pr.rbx, (int)r.rax);
            }

            break;

        case __NR_setgid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS setgid (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_setpgid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS setpgid (%d, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx, toerror(r.rax));
            }

            break;

        case __NR_kill:

            if (SDCOND) {
                indent(0);
                debug("%sSYS kill (%d, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx, toerror(r.rax));

                if (!T_nodesc) {
                    indent(0);
                    debug("+ signal %d = %s\n", (int)current->pr.rcx, strsignal(current->pr.rcx));
                }
            }

            break;

        case __NR_sigaction:
        case __NR_rt_sigaction:

            {                   // Restore changed memory structure. Don't
                                // bother for int3.
                unsigned int addr;
                addr = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);

                if (addr)
                    if ((addr >> 24) == CODESEG)
                        ptrace(PTRACE_POKEDATA, pid, current->pr.rcx, addr + 1);

            }

            if (SDCOND) {
                unsigned long int oldh = 0, newh = 0;
                indent(0);

                if (r.rax == -EFAULT) {

                    debug("%sSYS sigaction (%d, %x, %x) = %s\n", in_libc ? "[L] " : "",
                          (int)current->pr.rbx, (int)current->pr.rcx, (int)current->pr.rdx, toerror(r.rax));

                } else {

                    if (current->pr.rdx)
                        oldh = ptrace(PTRACE_PEEKDATA, pid, current->pr.rdx, 0);
                    if (current->pr.rcx)
                        newh = ptrace(PTRACE_PEEKDATA, pid, current->pr.rcx, 0);

                    pdescr[0] = 0;
                    debug("%sSYS sigaction (%d, %x [h:%lx], %x [h:%lx]) = %s\n", in_libc ? "[L] " : "",
                          (int)current->pr.rbx, Xv(current->pr.rcx), newh, Xv(current->pr.rdx), oldh, toerror(r.rax));
                    dump_pdescr(0);

                    if (!T_nodesc) {

                        indent(0);
                        debug("+ signal %d = %s\n", (int)current->pr.rbx, strsignal(current->pr.rbx));

                        if (current->pr.rdx) {
                            indent(0);
                            if (oldh == (long int)SIG_IGN) {
                                debug("+ 0x%lx = SIG_IGN\n", oldh);
                            } else if (oldh == (long int)SIG_DFL) {
                                debug("+ 0x%lx = SIG_DFL\n", oldh);
                            } else {
                                debug("+ 0x%lx = %s\n", oldh, lookup_fnct(oldh, 1, 1));
                            }
                            add_mem(current->pr.rcx, sizeof(struct sigaction), 0, b2, 0);
                        }

                        if (current->pr.rcx) {
                            indent(0);
                            if (newh == (long int)SIG_IGN) {
                                debug("+ 0x%lx = SIG_IGN\n", newh);
                                remove_handler(current->pr.rbx);
                            } else if (newh == (long int)SIG_DFL) {
                                debug("+ 0x%lx = SIG_DFL\n", newh);
                                remove_handler(current->pr.rbx);
                            } else {
                                debug("+ 0x%lx = %s\n", newh, lookup_fnct(newh, 1, 1));
                                add_handler(current->pr.rbx, newh);
                            }
                            add_mem(current->pr.rdx, sizeof(struct sigaction), 0, b2, 0);
                        }

                    }

                }

            }

            break;

        case __NR_sigsuspend:
        case __NR_rt_sigsuspend:

            if (SDCOND) {
                char mask[8];
                indent(0);
                if (r.rax != -EFAULT) {
                    AS_UINT(mask[0]) = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx, 0);
                    AS_UINT(mask[4]) = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4, 0);

                    pdescr[0] = 0;
                    debug("%sSYS sigsuspend (%x [%08x%08x]) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), AS_UINT(mask[0]), AS_UINT(mask[4]), toerror(r.rax));
                    dump_pdescr(0);
                    add_mem(current->pr.rbx, sizeof(sigset_t), 0, b2, 0);
                } else {
                    debug("%sSYS sigsuspend (%x) = %s\n", in_libc ? "[L] " : "", Xv(current->pr.rbx), toerror(r.rax));
                }
            }
            break;

        case __NR_sigpending:
        case __NR_rt_sigpending:

            if (SDCOND) {
                char mask[8];
                indent(0);
                if (r.rax != -EFAULT) {
                    AS_UINT(mask[0]) = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx, 0);
                    AS_UINT(mask[4]) = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4, 0);

                    pdescr[0] = 0;
                    debug("%sSYS sigpending (%x [%08x%08x]) = %s\n", in_libc ? "[L] " : "",
                          Xv(current->pr.rbx), AS_UINT(mask[0]), AS_UINT(mask[4]), toerror(r.rax));
                    dump_pdescr(0);
                    add_mem(current->pr.rbx, sizeof(sigset_t), 0, b2, 0);
                    modify_lasti(current->pr.rbx, b2, 0, 0, 0);
                } else {
                    debug("%sSYS sigpending (%x) = %s\n", in_libc ? "[L] " : "", Xv(current->pr.rbx), toerror(r.rax));
                }
            }

            break;

        case __NR_signal:

            if (SDCOND) {
                indent(0);
                debug("%sSYS signal (%d, 0x%x) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx, toerror(r.rax));

                if (!T_nodesc) {
                    indent(0);
                    debug("+ signal %d = %s\n", (int)current->pr.rbx, strsignal(current->pr.rbx));
                }

                if (!T_nodesc) {
                    indent(0);
                    if (current->pr.rcx == (long int)SIG_IGN) {
                        debug("+ 0x%x = SIG_IGN\n", (int)current->pr.rcx);
                        remove_handler(current->pr.rbx);
                    } else if (current->pr.rcx == (long int)SIG_DFL) {
                        debug("+ 0x%x = SIG_DFL\n", (int)current->pr.rcx);
                        remove_handler(current->pr.rbx);
                    } else {
                        debug("+ 0x%x = %s\n", (int)current->pr.rcx, lookup_fnct(current->pr.rcx, 1, 1));
                        add_handler(current->pr.rbx, current->pr.rcx);

                    }
                }
            }

            break;

        case __NR_nice:

            if (SDCOND) {
                indent(0);
                debug("%sSYS nice (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_alarm:

            if (SDCOND) {
                indent(0);
                debug("%sSYS alarm (%d) = %d\n", in_libc ? "[L] " : "", (int)current->pr.rbx, (int)r.rax);
            }

            break;

        case __NR_getpid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getpid () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_getpgid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getpgid (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_getsid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getsid (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_personality:

            if (SDCOND) {
                indent(0);
                debug("%sSYS personality (0x%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_getpgrp:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getpgrp () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_getppid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getppid () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_pause:

            if (SDCOND) {
                indent(0);
                debug("%sSYS pause () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_getuid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getuid () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_getgid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getgid () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_flock:

            if (SDCOND) {
                indent(0);
                buf[0] = 0;
                if (current->pr.rbx & LOCK_SH) {
                    current->pr.rbx -= LOCK_SH;
                    strcpy(buf, "LOCK_SH");
                }
                if (current->pr.rbx & LOCK_EX) {
                    current->pr.rbx -= LOCK_EX;
                    if (buf[0])
                        strcat(buf, " | ");
                    strcat(buf, "LOCK_EX");
                }
                if (current->pr.rbx & LOCK_UN) {
                    current->pr.rbx -= LOCK_UN;
                    if (buf[0])
                        strcat(buf, " | ");
                    strcat(buf, "LOCK_UN");
                }
                if (current->pr.rbx & LOCK_NB) {
                    current->pr.rbx -= LOCK_NB;
                    if (buf[0])
                        strcat(buf, " | ");
                    strcat(buf, "LOCK_NB");
                }
                if (current->pr.rbx) {
                    if (buf[0])
                        strcat(buf, " | ");
                    sprintf(&buf[strlen(buf)], "0x%x", (int)current->pr.rbx);
                }

                pdescr[0] = 0;
                debug("%sSYS flock (%d, %s) = %s\n", in_libc ? "[L] " : "", Xf(current->pr.rbx), buf, toerror(r.rax));
                dump_pdescr(0);
            }

            break;

        case __NR_msync:

            if (SDCOND) {
                indent(0);
                if (current->pr.rdx == MS_ASYNC)
                    strcpy(buf, "MS_ASYNC");
                else if (current->pr.rdx == MS_SYNC)
                    strcpy(buf, "MS_SYNC");
                else if (current->pr.rdx == MS_INVALIDATE)
                    strcpy(buf, "MS_INVALIDATE");
                else
                    sprintf(buf, "0x%x", (int)current->pr.rdx);

                pdescr[0] = 0;
                debug("%sSYS msync (%x, %d, %s) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), (int)current->pr.rcx, buf, toerror(r.rax));
                dump_pdescr(0);
            }

            break;

        case __NR_mlock:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;
                debug("%sSYS mlock (%x, %d) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);
            }

            break;

        case __NR_mlockall:

            if (SDCOND) {
                indent(0);

                debug("%sSYS mlockall (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rcx, toerror(r.rax));
            }

            break;

        case __NR_munlockall:

            if (SDCOND) {
                indent(0);

                debug("%sSYS munlockall () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_munlock:

            if (SDCOND) {
                indent(0);

                pdescr[0] = 0;
                debug("%sSYS munlock (%x, %d) = %s\n", in_libc ? "[L] " : "",
                      Xv(current->pr.rbx), (int)current->pr.rcx, toerror(r.rax));
                dump_pdescr(0);
            }

            break;

        case __NR_vhangup:

            if (SDCOND) {
                indent(0);
                debug("%sSYS vhangup () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_iopl:

            if (SDCOND) {
                indent(0);
                debug("%sSYS iopl (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_vm86old:

            if (SDCOND) {
                indent(0);
                debug("%sSYS vm86old (0x%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_vm86:

            if (SDCOND) {
                indent(0);
                debug("%sSYS vm86old (%d, 0x%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx,
                      (int)current->pr.rcx, toerror(r.rax));
            }

            break;

        case __NR_idle:

            if (SDCOND) {
                indent(0);
                debug("%sSYS idle() = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_ioperm:

            if (SDCOND) {
                indent(0);
                debug("%sSYS ioperm (%d, %d, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx, (int)current->pr.rdx, toerror(r.rax));
            }

            break;

        case __NR_fork:
        case __NR_vfork:

            if (SDCOND) {
                indent(0);
                debug("%sSYS fork () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }
            install_traps();

            break;

        case __NR_getpriority:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getpriority (%d, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx, toerror(r.rax));
            }

            break;

        case __NR_setpriority:

            if (SDCOND) {
                indent(0);
                debug("%sSYS setpriority (%d, %d, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx, (int)current->pr.rdx, toerror(r.rax));
            }

            break;

        case __NR_sgetmask:

            if (SDCOND) {
                indent(0);
                debug("%sSYS sgetmask () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_ssetmask:

            if (SDCOND) {
                indent(0);
                debug("%sSYS ssetmask (%d) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_brk:

            if (SDCOND) {
                indent(0);
                debug("%sSYS brk (0x%x) = %s\n", in_libc ? "[L] " : "", (int)current->pr.rbx, toerror(r.rax));
            }

            break;

        case __NR_sync:

            if (SDCOND) {
                indent(0);
                debug("%sSYS sync () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_geteuid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS geteuid () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_getegid:

            if (SDCOND) {
                indent(0);
                debug("%sSYS getegid () = %s\n", in_libc ? "[L] " : "", toerror(r.rax));
            }

            break;

        case __NR_mmap:

            {
                // Now, this is sick, sick, sick!
                int fd, len;
                unsigned int flags;
                unsigned int addr, off, prot;

                len = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4 * 1, 0);
                flags = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4 * 3, 0);
                fd = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4 * 4, 0);

                if (SDCOND) {

                    indent(0);
                    prot = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4 * 2, 0);
                    off = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4 * 5, 0);
                    addr = ptrace(PTRACE_PEEKDATA, pid, current->pr.rbx + 4 * 0, 0);

                    b3[0] = 0;

                    if (prot & PROT_READ) {
                        prot -= PROT_READ;
                        strcat(b3, "PROT_READ");
                    }
                    if (prot & PROT_WRITE) {
                        prot -= PROT_WRITE;
                        if (strlen(b3))
                            strcat(b3, " | ");
                        strcat(b3, "PROT_WRITE");
                    }
                    if (prot & PROT_EXEC) {
                        prot -= PROT_EXEC;
                        if (strlen(b3))
                            strcat(b3, " | ");
                        strcat(b3, "PROT_EXEC");
                    }
                    if (prot) {
                        if (strlen(b3))
                            strcat(b3, " | ");
                        sprintf(&b3[strlen(b3)], "0x%x", prot);
                    }
                    if (!strlen(b3))
                        strcpy(b3, "PROT_NONE");

                    buf[0] = 0;
                    if (flags & MAP_SHARED) {
                        flags -= MAP_SHARED;
                        strcat(buf, "MAP_SHARED");
                    }
                    if (flags & MAP_PRIVATE) {
                        flags -= MAP_PRIVATE;
                        if (strlen(buf))
                            strcat(buf, " | ");
                        strcat(buf, "MAP_PRIVATE");
                    }
                    if (flags & MAP_FIXED) {
                        flags -= MAP_FIXED;
                        if (strlen(buf))
                            strcat(buf, " | ");
                        strcat(buf, "MAP_FIXED");
                    }
                    if (flags & MAP_ANONYMOUS) {
                        flags -= MAP_ANONYMOUS;
                        if (strlen(buf))
                            strcat(buf, " | ");
                        strcat(buf, "MAP_ANONYMOUS");
                    }
                    if (flags) {
                        if (strlen(buf))
                            strcat(buf, " | ");
                        sprintf(&buf[strlen(buf)], "0x%x", flags);
                    }
                    if (!strlen(buf))
                        strcpy(buf, "0");

                    pdescr[0] = 0;

                    if (r.rax < 0) {
                        debug("%sSYS mmap (0x%x, %d, %s, %s, %d, %d) = %s\n",
                              in_libc ? "[L] " : "", addr, len, b3, buf, Xf(fd), off, toerror(r.rax));
                    } else {
                        debug("%sSYS mmap (0x%x, %d, %s, %s, %d, %d) = 0x%08x\n",
                              in_libc ? "[L] " : "", addr, len, b3, buf, Xf(fd), off, (unsigned int)r.rax);
                    }

                    dump_pdescr(0);

                }

                if (INLIBC(r.rax))
                    if (!(flags & MAP_ANONYMOUS))
                        add_map(fd, r.rax, len, b2);

            }

            break;

        case __NR_munmap:

            if (SDCOND) {
                indent(0);
                debug("%sSYS munmap (0x%x, %d) = %s\n", in_libc ? "[L] " : "",
                      (int)current->pr.rbx, (int)current->pr.rcx, toerror(r.rax));
            }

            if (!r.rax)
                delete_map(current->pr.rbx);
            break;

        default:

            if (SDCOND) {
                indent(0);
                debug("%sSYS%d %s ??? (", in_libc ? "[L] " : "", current->syscall,
                      // FIXME: hardcoded?!? more than 300+ for i386
                      scnames[current->syscall & 0xff]);
                pdescr[0] = 0;
                display_value(current->pr.rbx, b2);
                debug(", ");
                display_value(current->pr.rcx, b2);
                debug(", ");
                display_value(current->pr.rdx, b2);
                debug(") = ");
                display_value(r.rax, b2);
                debug("\n");
                dump_pdescr(0);
            }

    }

    pdescr[0] = 0;

}

char find_id_buf[100];

char *find_id_off(unsigned int c)
{
    unsigned int i = 0;
    int best = -1, bestdiff = -(PRETTYSMALL);

    if (!current->fnaddr)
        return 0;
    if ((c >> 24) != CODESEG)
        return 0;

    for (i = 0; i < current->idtop; i++)
        if ((*current->fnaddr)[i] <= c) {
            int diff = c - (*current->fnaddr)[i];
            if (diff < bestdiff) {
                bestdiff = diff;
                best = i;
            }
        }

    if (best < 0)
        return 0;

    if (bestdiff)
        sprintf(find_id_buf, "fnct_%d+%d", best + 1, bestdiff);
    else
        sprintf(find_id_buf, "fnct_%d", best + 1);

    return find_id_buf;

}

void found_fnprint(int count, struct fenris_fndb *cur, int fprint, int unused __attribute__ ((unused)))
{
    if (!count)
        debug("# Matches for signature %08X: ", fprint);
    debug("%s ", cur->name);
}

void finish_fnprint(int count, int fprint, int unused __attribute__ ((unused)))
{
    if (count)
        debug("\n");
    else
        debug("# No matches for signature %08X.\n", fprint);
}

/******************************
 * Handle local function call *
 ******************************/

void handle_fncall(const char how)
{
    char *f = "fnct_bogus";
    unsigned int prev;

    current->justcalled = 1;
    if (current->nest < -1)
        return;

    current->anything = 1;

    indent(0);
    current->nest++;
    if (current->nest >= MAXNEST) {
        if (T_noskip) {
            debug("* WARNING: MAXNEST exceeded at 0x%x, pretending that nothing happened.\n", (int)r.rip);
            current->nest--;
        } else
            fatal("MAXNEST exceeded in handle_fncall", 0);
    }
    current->isfnct[current->nest - 1] = 1;

    // bzero(current->pstack[current->nest],MFNN*4);
    current->pst_top[current->nest] = 0;

    current->fncalls++;

    if (how) {
        prev = current->idtop;
        debug("%ssignal handler %s (...)\n", in_libc ? "[L] " : "", f = lookup_fnct(caddr, 1, 1));
        push_fnid(find_id(caddr, 0));
        if (current->idtop != prev) {
            if (!T_nodesc) {
                indent(-1);
                debug("+ %s = 0x%x\n", lookup_fnct((*current->fnaddr)[current->idtop - 1], 0, 1), caddr);
            }
        }

        dump_pdescr(-1);
        return;
    }

    prev = current->idtop;

    debug("%slocal %s (", in_libc ? "[L] " : "", f = lookup_fnct(caddr, 1, 1));

    {
        char n[MAXDESCR];
        char *q = strdup(f);
        if (prev - 1)
            sprintf(n, "F %s:%s", lookup_fnct((*current->fnaddr)[prev - 2], 0, 1), q);
        else
            sprintf(n, "F main:%s", q);
        free(q);

        display_fparams(r.rsp, current->curpcnt, n);
    }

    debug(")\n");
    push_fnid(find_id(caddr, 0));

    if (current->idtop != prev) {
        if (!T_nodesc) {
            indent(-1);
            debug("+ %s = 0x%x\n", lookup_fnct((*current->fnaddr)[current->idtop - 1], 0, 1), caddr);
        }
    }

    dump_pdescr(-1);

    if (!current->is_static || T_nosig) {
        if (T_dostep)
            break_call(caddr);
        return;
    }
    if (strncmp(f, "fnct_", 5)) {
        if (T_dostep)
            break_call(caddr);
        return;
    }

    {
        int i;
        unsigned char sig[SIGNATSIZE + 4];

        for (i = 0; i < SIGNATSIZE / 4; i++)
            AS_UINT(sig[i * 4]) = ptrace(PTRACE_PEEKDATA, pid, caddr + i * 4, 0);

        indent(-1);
        find_fnprints(fnprint_compute(sig, CODESEG), found_fnprint, finish_fnprint, 0);

    }

    if (T_dostep)
        break_call(caddr);

}

/********************
 * Handle libc call *
 ********************/

void handle_libcall(void)
{

    if (current->nest < -1)
        return;

    current->jmplibc = 0;
    current->nest++;
    if (current->nest >= MAXNEST) {
        if (T_noskip) {
            debug("* WARNING: MAXNEST exceeded at 0x%x, pretending that nothing happened.\n", (int)r.rip);
            current->nest--;
        } else
            fatal("MAXNEST exceeded in handle_libcall", 0);
    }
    current->isfnct[current->nest - 1] = 0;

    current->anything = 1;

    // bzero(current->pstack[current->nest],MFNN*4);
    current->pst_top[current->nest] = 0;

    current->libcalls++;

    // debug("entering libc by jumping to 0x%x at 0x%x\n",caddr,r.rip);

    // HUH HUH?
    if (!T_dostep)
        if (current->getname)
            fatal("double getname attempt", 0);

    current->getname = 1;
    current->pr.rsp = r.rsp;
    current->lentry = caddr;

}

/*****************************************
 * Delayed display of libcall parameters *
 *****************************************/

void display_libcall(unsigned int c)
{
    char *name = find_name(c);

    if (!strncmp(name, "_IO_", 4))
        name += 4;
    else if (!strncmp(name, "__libc_", 7))
        name += 7;
    else if (!strncmp(name, "__", 2))
        name += 2;

    if (current->nest < -1)
        return;

    pdescr[0] = 0;

    if (current->jmplibc) {
        indent(-1);
        debug("...left function w/o returning (JMP into lib)\n");
        if (current->nest > 0)
            current->isfnct[current->nest - 1] = 0;
        dump_memchg(-1);
        current->jmplibc = 0;
    }

    if (!check_specific(name, current->pr.rsp, current->curpcnt)) {
        char n[MAXDESCR];
        indent(-1);
        debug("U %s (", name);

        if (current->idtop)
            sprintf(n, "U %s:%s", lookup_fnct((*current->fnaddr)[current->idtop - 1], 0, 1), name);
        else
            sprintf(n, "U main:%s", name);

        display_fparams(current->pr.rsp, current->curpcnt, n);
        debug(")\n");
        dump_pdescr(-1);
    }

    current->getname = 0;
    current->donottouch = 0;

    if (T_dostep)
        break_libcall(c);

}

/*******************************
 * Handle return from function *
 *******************************/

void handle_ret(void)
{
    unsigned int retto;

    if (current->nest == 0 && !current->anything) {
        current->atret = 1;
        current->nest = -1;
    }

    if (current->nest < 0 && !current->atret)
        return;

    if (in_libc) {
        retto = ptrace(PTRACE_PEEKDATA, pid, r.rsp, 0);
        if (INLIBC(retto))
            return;
    }
    // else {
    // if (((retto >> 24) == LIBCSEG)) debug("Return into libc at
    // 0x%x!!!\n",retto);
    // }

    if (current->atret) {
        if (!(--current->atret)) {
            current->nest = 0;
#ifdef HEAVY_DEBUG
            debug("entered dynamic at 0x%x (%s)\n", (int)r.rip, lookup_fnct(r.rip, 0, 0));
#endif /* HEAVY_DEBUG */
        }
        return;
    }

    pdescr[0] = 0;

    if ((--current->nest) == -1) {

        if (!(innest) || T_noskip) {
            current->nest = 0;
            current->pst_top[0] = 0;
            CURPCNT(0) = 0;
        } else
            current->nest = PRETTYSMALL;

        if (T_noindent)
            debug("...return from %s = ", stop_rip ? "partial trace segment" : "main()");
        else {
            if (T_addip)
                debug("[%08x] ", (int)r.rip);
            debug("%d:-- ...return from %s = ", pid, stop_rip ? "partial trace segment" : "main()");
        }
        if (current->retpar || T_alwaysret) {
            display_value(r.rax, "<ret from main>");
            debug("\n");
        } else
            debug("<void>\n");
        dump_pdescr(0);
        dump_memchg(0);
        if (current->nest == PRETTYSMALL) {
            break_newline();
            debug("+++ Process %d detached (outside traceable code) +++\n", current->pid);
            ptrace(PTRACE_DETACH, current->pid, 0, 0);
            remove_process();
        }
        return;
    }

    indent(0);

    if (in_libc) {

        if (current->getname) {
            debug("STRANGE %s () \n", find_name(current->lentry));
            current->getname = 0;
            indent(0);
        }

        else if (current->lcname[0]) {
            display_specific();
            current->lcname[0] = 0;
        }

        else {
            debug("...return from libc = ");
            display_value(r.rax, "<ret from libc>");
            debug("\n");
        }

        dump_pdescr(0);

    } else {
        debug("...return from function = ");

        if (current->retpar || T_alwaysret) {
            display_value(r.rax, "<ret from fn>");
            debug("\n");
        } else
            debug("<void>\n");

        dump_pdescr(0);
        fn_ret();
        if (T_dostep)
            break_nestdown();
        if (T_dostep)
            break_ret();

    }

}

/*****************************
 * Handle subfunction params *
 *****************************/

void handle_subesp(int x, unsigned char next)
{
    unsigned char buf[4];

    if (current->nest < 0)
        return;

    if (in_libc)
        return;

    AS_UINT(buf[0]) = ptrace(PTRACE_PEEKDATA, pid, r.rip - 3, 0);

    /* Eat this: 8049a81: 83 c4 10 add $0x10,%esp 8049a84: 83 ec 04 sub
       $0x4,%esp */

    if (next != 0xbb)
        x = 0;
    else {
        if (buf[0] == 0x83 && buf[1] == 0xc4)
            x = 1 + (x - (int)buf[2]) / 4;
        else
            x = 0;
        // if (x) debug("SUBESP ADJUST () = %d\n",x);
    }

    current->pst_top[current->nest]++;
    if (current->pst_top[current->nest] >= MFNN)
        fatal("mfnn exceeded", 0);
    CURPCNT(0) = x;

}

void handle_subesp_long(int x, unsigned char next)
{
    unsigned char buf[8];

    if (current->nest < 0)
        return;

    if (in_libc)
        return;

    AS_UINT(buf[0]) = ptrace(PTRACE_PEEKDATA, pid, r.rip - 6, 0);
    AS_UINT(buf[4]) = ptrace(PTRACE_PEEKDATA, pid, r.rip - 2, 0);

    /* Eat this: 8049a81: 81 c4 xx xx xx xx 8049a84: 81 ec xx xx xx xx */

    if (next != 0xbb)
        x = 0;
    else {
        if (buf[0] == 0x81 && buf[1] == 0xc4)
            x = 1 + (x - (int)AS_UINT(buf[2])) / 4;
        else
            x = 0;
        // if (x) debug("SUBESP ADJUST () = %d\n",x);
    }

    current->pst_top[current->nest]++;
    if (current->pst_top[current->nest] >= MFNN)
        fatal("mfnn exceeded", 0);
    CURPCNT(0) = x;

}

/*************************
 * Dispose relative CALL *
 *************************/

void handle_call(void)
{
    unsigned int there;

    caddr = AS_UINT(op[1]) + 5 + r.rip;

    if (in_libc)
        if (INLIBC(caddr))
            return;

    if (current->nest >= 0) {
        current->curpcnt = CURPCNT(0);
        CURPCNT(0) = 0;
        current->pst_top[current->nest]--;
        if (current->pst_top[current->nest] < 0)
            current->pst_top[current->nest] = 0;
    }

    current->ncalls++;

    there = ptrace(PTRACE_PEEKDATA, pid, caddr, 0);

    if ((there & 0xffff) == 0x25ff /* JMP */ ) {
        if (!in_libc)
            handle_libcall();
    } else
        handle_fncall(0);

}

/*************************
 * Dispose absolute call *
 *************************/

void handle_abscall(void)
{
    unsigned int there;

    caddr = ptrace(PTRACE_PEEKDATA, pid, AS_UINT(op[2]), 0);

    if (in_libc)
        if (INLIBC(caddr))
            return;

    if (current->nest >= 0) {
        current->curpcnt = CURPCNT(0);
        CURPCNT(0) = 0;
        current->pst_top[current->nest]--;
        if (current->pst_top[current->nest] < 0)
            current->pst_top[current->nest] = 0;
    }

    current->ncalls++;

    there = ptrace(PTRACE_PEEKDATA, pid, caddr, 0);

    if ((there & 0xffff) == 0x25ff /* JMP */ ) {
        if (!in_libc)
            handle_libcall();
    } else
        handle_fncall(0);

}

/**************************
 * Handle dumb regoffcall *
 **************************/

void handle_regoffcall(unsigned int addr)
{
    unsigned int there;

    caddr = ptrace(PTRACE_PEEKDATA, pid, addr, 0);

    if (in_libc)
        if (INLIBC(caddr))
            return;

    if (current->nest >= 0) {
        current->curpcnt = CURPCNT(0);
        CURPCNT(0) = 0;
        current->pst_top[current->nest]--;
        if (current->pst_top[current->nest] < 0)
            current->pst_top[current->nest] = 0;
    }

    current->ncalls++;

    there = ptrace(PTRACE_PEEKDATA, pid, caddr, 0);

    if ((there & 0xffff) == 0x25ff /* JMP */ ) {
        if (!in_libc)
            handle_libcall();
    } else
        handle_fncall(0);

}

/***********
 * Moronic *
 ***********/

void handle_jmp(void)
{
    unsigned int there;

    caddr = AS_UINT(op[1]) + 5 + r.rip;

    if (in_libc)
        if (INLIBC(caddr))
            return;

    current->ncalls++;

    there = ptrace(PTRACE_PEEKDATA, pid, caddr, 0);

    if ((there & 0xffff) == 0x25ff /* JMP */ ) {
        if (current->getname)
            fatal("double getname attempt", 0);
        current->jmplibc = 1;
        current->getname = 1;
        current->pr.rsp = r.rsp;
        current->lentry = caddr;
        fn_ret();
    }

}

/*************************
 * Dispose register-call *
 *************************/

void handle_regcall(unsigned int reg)
{
    unsigned int there;

    caddr = reg;

    if (in_libc) {
        if (INLIBC(caddr))
            return;
        // This is not to report entry to main.
        if (current->nest == 0)
            return;
    }

    if (current->nest >= 0) {
        current->curpcnt = CURPCNT(0);
        CURPCNT(0) = 0;
        current->pst_top[current->nest]--;
        if (current->pst_top[current->nest] < 0)
            current->pst_top[current->nest] = 0;
    }

    if (INLIBC(caddr)) {
        handle_libcall();
        return;
    }

    there = ptrace(PTRACE_PEEKDATA, pid, caddr, 0);

    if ((there & 0xffff) == 0x25ff /* JMP */ ) {
        if (!in_libc)
            handle_libcall();
    } else
        handle_fncall(0);

}

/****************************
 * Handle some conditionals *
 ****************************/

void handle_je(int off)
{
    if (in_libc || current->intercept || (current->nest < 0))
        return;
    indent(0);
    debug("<%x> ", (int)r.rip);
    if (off > 0) {
        debug("cndt: conditional block %+d %s\n", off, FSET(F_ZERO) ? "skipped" : "executed");
    } else {
        debug("cndt: conditional block %+d %s\n", off, FSET(F_ZERO) ? "repeated" : "exited");
    }
}

void handle_jne(int off)
{
    if (in_libc || current->intercept || (current->nest < 0))
        return;
    indent(0);
    debug("<%x> ", (int)r.rip);
    if (off > 0) {
        debug("cndt: on-match block %+d %s\n", off, FSET(F_ZERO) ? "executed" : "skipped");
    } else {
        debug("cndt: on-match block %+d %s\n", off, FSET(F_ZERO) ? "exited" : "repeated");
    }
}

void handle_jle(int off)
{
    int c;
    if (in_libc || current->intercept || (current->nest < 0))
        return;
    indent(0);
    debug("<%x> ", (int)r.rip);
    // JLE Jump if less than or equal (<=) Sign != Ovrflw or Zero = 1
    c = FSET(F_ZERO) || (FSET(F_OVER) ^ FSET(F_SIGN));
    if (off > 0) {
        debug("cndt: if-above block (unsigned) %+d %s\n", off, c ? "skipped" : "executed");
    } else {
        debug("cndt: if-above block (unsigned) %+d %s\n", off, c ? "repeated" : "exited");
    }
}

void handle_jbe(int off)
{
    int c;
    if (in_libc || current->intercept || (current->nest < 0))
        return;
    indent(0);
    debug("<%x> ", (int)r.rip);
    // JBE Jump if below or equal (<=) Carry = 1 or Zero = 1
    c = FSET(F_CARRY) || FSET(F_ZERO);
    if (off > 0) {
        debug("cndt: if-below block (unsigned) %+d %s\n", off, c ? "skipped" : "executed");
    } else {
        debug("cndt: if-below block (unsigned) %+d %s\n", off, c ? "repeated" : "exited");
    }
}

void handle_jg(int off)
{
    int c;
    if (in_libc || current->intercept || (current->nest < 0))
        return;
    indent(0);
    debug("<%x> ", (int)r.rip);
    // JG Jump if greater than (>) Sign = Ovrflw and Zero = 0
    c = (FSET(F_SIGN) == FSET(F_OVER)) && FSET(F_ZERO);
    if (off > 0) {
        debug("cndt: if-above block (signed) %+d %s\n", off, c ? "skipped" : "executed");
    } else {
        debug("cndt: if-above block (signed) %+d %s\n", off, c ? "repeated" : "exited");
    }
}

void handle_ja(int off)
{
    if (in_libc || current->intercept || (current->nest < 0))
        return;
    indent(0);
    debug("<%x> ", (int)r.rip);
    // JB Jump if below (<) Carry = 1
    if (off > 0) {
        debug("cndt: if-below block (signed) %+d %s\n", off, FSET(F_CARRY) ? "skipped" : "executed");
    } else {
        debug("cndt: if-below block (signed) %+d %s\n", off, FSET(F_CARRY) ? "repeated" : "exited");
    }
}

/*******************************
 * Dynamic linker entry marker *
 *******************************/

void enter_dynamic(void)
{
    // debug("ENTERDYNAMIC --> already=%d rip=%x op=%x %x %x %x %x %x %x %x\n",
    // already_main,r.rip,op[0],op[1],op[2],op[3],op[4],op[5],op[6],op[7]);
    already_main = 1;
    if (T_dostep)
        break_enterdyn();
    if (!start_rip)
        if (current->nest < 0)
            current->atret = T_atret;
}

// This is a dummy code for strlen() only.
void minline(const char *what)
{
    if ((current->nest >= 0) && ((r.rip >> 24) == CODESEG)) {
        char buf[MAXDESCR];
        indent(0);
        pdescr[0] = 0;
        get_string_from_child(r.rdi, buf, sizeof(buf));
        debug("// Found possibly inlined '%s' at 0x%08x:\n", what, (int)r.rip);
        indent(0);
        debug("L %s (%x \"%s\") = ??? <inlined>\n", what, Xv(r.rdi), buf);
        dump_pdescr(0);
    }
}

/***********************************************************
 * Here we are supposed to fetch registers and opcode from *
 * traced process and to find appropriate handler for this *
 * case, if any...                                         *
 ***********************************************************/

// NOTE: this should be optimized. Hmm, JIT for first two bytes?

int first_getregs = 1;

void handle_process(void)
{
    unsigned int maddr, i;

  rethink:

    if (ptrace(PTRACE_GETREGS, pid, 0, &r)) {
        if (errno == ESRCH)
            return;
        else
            fatal("PTRACE_GETREGS failed", errno);

        if (first_getregs) {
            first_getregs = 0;
            if (is_static && (CODESEG != (r.rip >> 24)))
                debug("********************************************************************\n"
                      "* WARNING: This is a binary, but initial rip is not in what *\n"
                      "* I am told to consider a code segment. If you have difficulties   *\n"
                      "* tracing this code, please consider using -X 0x%02x option.         *\n"
                      "********************************************************************\n", (int)r.rip >> 24);
        }

    }

    if (T_goaway) {
        // Do some very basic handling not to break aegir.
        if (AS_USHORT(op[0]) == 0x80cd)
            current->syscall = r.rax;
        else
            current->syscall = 0;
        return;
    }
    // Apply reptable rules... uh...

    for (i = 0; i < reptop; i++) {
        if (reptable[i].ip == r.rip) {
            unsigned int x = ptrace(PTRACE_PEEKDATA, pid, reptable[i].ad);
            x = (x & 0xffffff00) + reptable[i].va;
            ptrace(PTRACE_POKEDATA, pid, reptable[i].ad, x);
            indent(0);
            debug("// rip 0x%x -  changed address 0x%x to 0x%02x.\n", reptable[i].ip, reptable[i].ad, reptable[i].va);
        } else if (!reptable[i].ip) {
            unsigned int x = ptrace(PTRACE_PEEKDATA, pid, reptable[i].ad);
            x = (x & 0xffffff00) + reptable[i].va;
            ptrace(PTRACE_POKEDATA, pid, reptable[i].ad, x);
            indent(0);
            debug("// Changed address 0x%x to 0x%02x.\n", reptable[i].ad, reptable[i].va);
            reptable[i].ip = 1;
        }
    }

    AS_UINT(op[0]) = ptrace(PTRACE_PEEKDATA, pid, r.rip, 0);
    AS_UINT(op[4]) = ptrace(PTRACE_PEEKDATA, pid, r.rip + 4, 0);

    in_libc = INLIBC(r.rip);

    if (!current)
        return;

    if (current->intercept) {
        if (!(--current->intercept)) {
            display_libcall(r.rip);
            current->checkc2 = 0;
        }
    }
    // Tick-tack.
    if (current->retpar)
        current->retpar--;

    // Collides with one of ctors signatures.
    if (AS_USHORT(op[0]) == 0xe589)
        if (current->nest >= 0 /* && !in_libc */ )
            if (CURPCNT(0) > 0)
                CURPCNT(0) = 0;

#ifdef HEAVY_DEBUG

    if (current->nest >= 0) {
        int diff;
        diff = abs(r.rip - oldip);
        if (diff > 10) {
            char *x, *y;
            char tmp[500];

            x = lookup_fnct(oldip, 0, 0);
            if (!x)
                x = find_name_ex(oldip, 2, 1);
            if (x) {
                strcpy(tmp, x);
                x = tmp;
            }
            y = lookup_fnct(r.rip, 0, 0);
            if (!y)
                y = find_name_ex(r.rip, 2, 1);
            if (x || y) {
                if (!x)
                    x = "<null>";
                if (!y)
                    y = "<null>";
                if (strcmp(x, y)) {
                    debug("*** rip change (%x -> %x) (%s -> %s): %x %x %x %x\n",
                          oldip, (int)r.rip, x, y, oldop[0], oldop[1], oldop[2], oldop[3]);
                }
            }
        }

    }

    oldip = r.rip;
    memcpy(oldop, op, sizeof(op));

#endif /* HEAVY_DEBUG */

    if (current->checka3) {
        current->checka3 = 0;
        if (!in_libc) {
#ifdef HEAVY_DEBUG
            debug("*** FF A3 TO CODE.\n");
#endif /* HEAVY_DEBUG */
            // current->nest++;
            // if (current->nest>=MAXNEST) fatal("MAXNEST exceeded in FF A3
            // handler",0);
            // current->pst_top[current->nest]=0;
            caddr = r.rip;
            r.rsp += 4;
            handle_fncall(0);
            return;
        }
    }
    // Handle things like libc calling code via linker... or whatever.

    if (current->checkc2) {
        current->checkc2 = 0;
        if (!in_libc) {
#ifdef HEAVY_DEBUG
            debug("** RET C2 SEGMENT CHANGE\n");
#endif /* HEAVY_DEBUG */
            caddr = r.rip;
            r.rsp += 4;         // Skip ret address, of course...
            handle_fncall(0);
            return;
        }
    }

    if (start_rip && (r.rip == start_rip)) {
        current->nest = 0;
        indent(0);
        debug("// Partial trace: forced start at rip 0x%x\n", start_rip);
    }

    if (stop_rip && (r.rip == stop_rip)) {
        indent(0);
        debug("// Partial trace: forced stop at rip 0x%x\n", stop_rip);

        while (--current->nest >= -1) {
            indent(0);
            debug("...function never returned (forced trace stop).\n");
            if (current->nest < 0 || current->isfnct[current->nest]) {
                dump_memchg(0);
                if (current->fntop)
                    current->fntop--;
            }
        }

        // current->nest=PRETTYSMALL;
        debug("+++ Process %d detached (forced trace stop) +++\n", current->pid);
        ptrace(PTRACE_DETACH, current->pid, 0, 0);
        remove_process();
        return;                 // Foo!

    }
    // if (current->nest>=0)
    // debug("[%d] %x: ASM %08x\n",pid,r.rip,AS_UINT(op[0]));

    // This is a bit time-expensive, but hell with it.
    if ((current->nest >= 0) && ((r.rip >> 24) == CODESEG) && (!current->justcalled)) {
        unsigned int i;
        for (i = 1; i <= current->signals; i++)
            if (get_handler(i) == r.rip) {
                unsigned int retaddr;
                // We should never see that. Do an emergency return.
                retaddr = ptrace(PTRACE_PEEKDATA, pid, r.rsp, 0);
                // debug("* Note: doing a forced return from a signal handler
                // at %x to %x.\n",r.rip,retaddr);
                handle_ret();
                r.rip = retaddr;
                r.rsp += 4;
                ptrace(PTRACE_SETREGS, pid, 0, &r);
                goto rethink;
            }
    } else
        current->justcalled = 0;

    // Handle E8 relative call used to enter functions.
    // E8 00 00 00 00 == -fPIC trampoline, not a real call.

    if ((op[0] == 0xe8) && AS_UINT(op[1]))
        handle_call();

    // Handle C++ absolute pointer call

    else if (AS_UINT(op[0]) == 0x15ff)
        handle_abscall();

    // Handle E9 relative JMP, bah, stupid.

    else if (op[0] == 0xe9)
        handle_jmp();

    // Handle CALL *%reg, frequent in stuff like bsearch(), scandir(),
    // this might lead us back from libc to our code and such. Well,
    // actually every attempt to follow pointer to function would look
    // this way. Lucky me!

    else if (AS_USHORT(op[0]) == 0xd0ff)
        handle_regcall(r.rax);
    else if (AS_USHORT(op[0]) == 0xd1ff)
        handle_regcall(r.rcx);
    else if (AS_USHORT(op[0]) == 0xd2ff)
        handle_regcall(r.rdx);
    else if (AS_USHORT(op[0]) == 0xd3ff)
        handle_regcall(r.rbx);
    else if (AS_USHORT(op[0]) == 0xd6ff)
        handle_regcall(r.rsi);
    else if (AS_USHORT(op[0]) == 0xd7ff)
        handle_regcall(r.rdi);

    // Handle terribly stupid reg off calls... we skip 0x18(%edi,%esi,1) things
    // for now.

    else if (AS_USHORT(op[0]) == 0x55ff)
        handle_regoffcall((char)op[2] + (int)r.rbp);
    else if (AS_USHORT(op[0]) == 0x93ff)
        handle_regoffcall(AS_UINT(op[2]) + (int)r.rbx);
    else if (AS_USHORT(op[0]) == 0x56ff)
        handle_regoffcall((char)op[2] + (int)r.rsi);
    else if (AS_USHORT(op[0]) == 0x52ff)
        handle_regoffcall((char)op[2] + (int)r.rdx);
    else if (AS_USHORT(op[0]) == 0x51ff)
        handle_regoffcall((char)op[2] + (int)r.rcx);
    else if (AS_USHORT(op[0]) == 0x57ff)
        handle_regoffcall((char)op[2] + (int)r.rdi);
    else if (AS_USHORT(op[0]) == 0x50ff)
        handle_regoffcall((char)op[2] + (int)r.rax);

    // Check for RET (C2)...
    else if ((current->nest >= 0) && (AS_USHORT(op[0]) == 0x08c2)       /* &&
                                                                           in_libc 
                                                                         */ )
        current->checkc2 = 1;

    // Check for funny C++ JMP.
    else if ((current->nest >= 0) /* && in_libc */ &&(AS_USHORT(op[0]) == 0xa3ff))
        current->checka3 = 1;

    // Handle RET (C3), to keep track of our tracks ;)

    else if (op[0] == 0xc3) {
        handle_ret();
        if (!current)
            return;
    }
    // Handle MOV %rax, %rax by setting up retpar counter
    else if (AS_USHORT(op[0]) == 0xc089)
        current->retpar = 3;

    // Handle MOV $imm, %rax
    else if (op[0] == 0xb8)
        current->retpar = 3;

    // Handle INT $0x80 (CD 80), syscall entry point

    else if (AS_USHORT(op[0]) == 0x80cd) {
        handle_syscall();
        if (!current)
            return;             // It might have happened.
    }
    // Handle one LEA
    else if (AS_USHORT(op[0]) == 0x458d) {
        if (current->nest >= 0 /* && !in_libc */ )
            if (CURPCNT(0) < 0)
                CURPCNT(0) = 0;
    }
    // Handle POPs
    else if (op[0] == 0x58 || op[0] == 0x59 || op[0] == 0x5a || op[0] == 0x5b ||
             op[0] == 0x5d || op[0] == 0x5e || op[0] == 0x5f) {

        if (current->nest >= 0 /* && !in_libc */ )
            CURPCNT(0) = 0;
    }

    else if (AS_USHORT(op[0]) == 0xc483) {
        if (current->nest >= 0 /* && !in_libc */ )
            if (CURPCNT(0) > 0)
                CURPCNT(0) = 0;
    }
    // Handle SUB $imm,%esp (83 EC xx) used to delimit parameter pushing
    // Ah, sometimes it can be 81 EC.

    else if (AS_USHORT(op[0]) == 0xec83)
        handle_subesp((unsigned int)op[2], op[3]);
    else if (AS_USHORT(op[0]) == 0xec81)
        handle_subesp_long(AS_UINT(op[2]), op[6]);

    // Handle several variants of PUSH and MOV to the stack by
    // increasing parameter counter - but evaluate this complex
    // condition only if this happens locally, not in libc.

    else if ( /* (!in_libc) && */ (
                                      (op[0] == 0x50) || (op[0] == 0x51) || (op[0] == 0x52) ||
                                      (op[0] == 0x54) || (op[0] == 0x53) || (op[0] == 0x56) ||
                                      (op[0] == 0x55) ||
                                      (op[0] == 0x57) || (op[0] == 0x6a) || (op[0] == 0x68) ||
                                      (AS_USHORT(op[0]) == 0x75ff) || (AS_USHORT(op[0]) == 0x35ff) ||
                                      (AS_USHORT(op[0]) == 0x30ff) ||
                                      (AS_USHORT(op[0]) == 0x33ff) || (AS_USHORT(op[0]) == 0xb5ff) ||
                                      (AS_USHORT(op[0]) == 0xb4ff) || (AS_USHORT(op[0]) == 0x74ff) ||
                                      (AS_USHORT(op[0]) == 0x70ff) ||
                                      ((AS_USHORT(op[0]) == 0x0489) && (op[2] == 0x24)) ||
                                      ((AS_USHORT(op[0]) == 0x04c7) && (op[2] == 0x24)) ||
                                      ((AS_USHORT(op[0]) == 0x1c89) && (op[2] == 0x24)))) {
        if (current->nest >= 0)
            CURPCNT(0)++;
    }
    // libc 2.1, libc 2.2:
    // (gdb) x/8b __do_global_ctors_aux+6
    // This seems to be a constant piece of glibc _init outro.

    else if ((AS_UINT(op[0]) == 0x8353e589) && (AS_UINT(op[4]) == 0xf88304ec))
        enter_dynamic();

    // From space
    else if ((AS_UINT(op[0]) == 0x768d1674) && (AS_UINT(op[4]) == 0x27bc8d00))
        enter_dynamic();

    // libc 2.0
    // (gdb) x/8b __do_global_ctors_aux+48
    // This seems to be another constant piece, if +6 fails...

    else if ((AS_UINT(op[0]) == 0x89f85d8b) && (AS_UINT(op[4]) == 0x89c35dec))
        enter_dynamic();

    // reported case:
    // (gdb) x/8b __do_global_ctors_aux+19

    else if ((AS_UINT(op[0]) == 0x038b0c74) && (AS_UINT(op[4]) == 0xfffcc383))
        enter_dynamic();

    // RH 7.3
    else if ((AS_UINT(op[0]) == 0x768d1274) && (AS_UINT(op[4]) == 0x007f8d00))
        enter_dynamic();

    else if ((AS_UINT(op[0]) == 0x038b0c74) && (AS_UINT(op[4]) == 0xc383d0ff))
        enter_dynamic();

    // PLD and others. Funny.

    else if ((AS_UINT(op[0]) == 0xeb830c74) && (AS_UINT(op[4]) == 0x8bd0ff04))
        enter_dynamic();

    else if ((AS_UINT(op[0]) == 0x038b0d74) && (AS_UINT(op[4]) == 0xc383d0ff))
        enter_dynamic();

    // +20

    else if ((AS_UINT(op[0]) == 0x768d1274) && (AS_UINT(op[4]) == 0x007f8d00))
        enter_dynamic();

    // +16 from OWL
    else if ((AS_UINT(op[0]) == 0x038b0c74) && (AS_UINT(op[4]) == 0xfffcc383))
        enter_dynamic();

    // reported case:
    // (gdb) x/8b __do_global_ctors_aux+11

    else if ((AS_UINT(op[0]) == 0x8904e883) && (AS_UINT(op[4]) == 0x768dfc45))
        enter_dynamic();

    // This is often inlined.
    else if ((AS_UINT(op[0]) == 0xffffffb9) && (AS_UINT(op[4]) == 0xf7aef2ff))
        minline("strlen");

    else if (!in_libc && (current->nest >= 0) && (op[0] == 0xcc)) {
        unsigned int i, got = 0;
        for (i = 1; i <= current->signals; i++)
            if (get_handler(i) == r.rip) {
                got = 1;
                break;
            }
        if (!got) {
            if (get_handler(SIGTRAP))
                debug("***************************************************************\n"
                      "* WARNING: I detected a debugger trap planted in the code at  *\n"
                      "* address 0x%08x. This int3 call is \"connected\" to a    *\n"
                      "* SIGTRAP handler at 0x%08x. Please use Aegir or nc-aegir *\n"
                      "* carefully remove this trap, see the documentation.          *\n"
                      "***************************************************************\n", (int)r.rip,
                      get_handler(SIGTRAP));
            else
                debug("************************************************************\n"
                      "* WARNING: I detected something that looks like a debugger *\n"
                      "* trap planted in the code at address 0x%08x. If you   *\n"
                      "* experience any problems, please use Aegir or nc-aegir to *\n"
                      "* carefully remove this trap, see the documentation.       *\n"
                      "************************************************************\n", (int)r.rip);
        }
    }
    // Handle other known assembler statements here...

    // Here are some conditional jumps. Hope I do not miss any,
    // but gcc 2.9 seems to stick to this subset.

    else if (!T_nocnd) {

        if (op[0] == 0x75)
            handle_jne((signed char)op[1]);
        else if (op[0] == 0x74)
            handle_je((signed char)op[1]);
        else if (op[0] == 0x7e)
            handle_jle((signed char)op[1]);
        else if (op[0] == 0x76)
            handle_jbe((signed char)op[1]);
        else if (op[0] == 0x7f)
            handle_jg((signed char)op[1]);
        else if (op[0] == 0x77)
            handle_ja((signed char)op[1]);

        else if (op[0] == 0x7c)
            handle_jle((signed char)op[1]);     // JL
        else if (op[0] == 0x72)
            handle_jbe((signed char)op[1]);     // JB
        else if (op[0] == 0x7d)
            handle_jg((signed char)op[1]);      // JGE
        else if (op[0] == 0x73)
            handle_ja((signed char)op[1]);      // JAE

        else if (AS_USHORT(op[0]) == 0x850f)
            handle_jne(AS_UINT(op[2]));
        else if (AS_USHORT(op[0]) == 0x840f)
            handle_je(AS_UINT(op[2]));
        else if (AS_USHORT(op[0]) == 0x8e0f)
            handle_jle(AS_UINT(op[2]));
        else if (AS_USHORT(op[0]) == 0x860f)
            handle_jbe(AS_UINT(op[2]));
        else if (AS_USHORT(op[0]) == 0x8f0f)
            handle_jg(AS_UINT(op[2]));
        else if (AS_USHORT(op[0]) == 0x870f)
            handle_ja(AS_UINT(op[2]));

        else if (AS_USHORT(op[0]) == 0x8c0f)
            handle_jle(AS_UINT(op[2])); // JL
        else if (AS_USHORT(op[0]) == 0x820f)
            handle_jbe(AS_UINT(op[2])); // JB
        else if (AS_USHORT(op[0]) == 0x8d0f)
            handle_jg(AS_UINT(op[2]));  // JGE
        else if (AS_USHORT(op[0]) == 0x830f)
            handle_ja(AS_UINT(op[2]));  // JAE

    }

    if (current->nest >= 0 && !in_libc && !T_nomem) {
        struct changed *CH;

        CH = disassemble_address(op, 1);

        if (CH->addr || CH->areg[0] || CH->ireg[0]) {
            maddr = CH->addr;

            if (CH->areg[0]) {
                if (CH->areg[1] == 'a')
                    maddr += r.rax;
                else if (CH->areg[1] == 'c')
                    maddr += r.rcx;
                else if (CH->areg[1] == 'b' && CH->areg[2] == 'x')
                    maddr += r.rbx;
                else if (CH->areg[1] == 'd' && CH->areg[2] == 'x')
                    maddr += r.rdx;
                else if (CH->areg[1] == 'd' && CH->areg[2] == 'i')
                    maddr += r.rdi;
                else if (CH->areg[1] == 's' && CH->areg[2] == 'i')
                    maddr += r.rsi;
                else if (CH->areg[1] == 'b' && CH->areg[2] == 'p')
                    maddr += r.rbp;
                else
                    goto exit_writecheck;
            }

            if (CH->ireg[0]) {
                if (CH->ireg[1] == 'a')
                    maddr += r.rax * CH->sc;
                else if (CH->ireg[1] == 'c')
                    maddr += r.rcx * CH->sc;
                else if (CH->ireg[1] == 'b' && CH->ireg[2] == 'x')
                    maddr += r.rbx * CH->sc;
                else if (CH->ireg[1] == 'd' && CH->ireg[2] == 'x')
                    maddr += r.rdx * CH->sc;
                else if (CH->ireg[1] == 'd' && CH->ireg[2] == 'i')
                    maddr += r.rdi * CH->sc;
                else if (CH->ireg[1] == 's' && CH->ireg[2] == 'i')
                    maddr += r.rsi * CH->sc;
                else if (CH->ireg[1] == 'b' && CH->ireg[2] == 'p')
                    maddr += r.rbp * CH->sc;
                else
                    goto exit_writecheck;
            }
            // Hell knows where. Report.
            if (T_dostep)
                break_memwrite(maddr);

            if ((maddr >> 24) != STACKSEG) {
                if ((maddr >> 24) != CODESEG) {
                    // debug("codeseg %x maddr %x\n",CODESEG,(maddr >> 24));
                    if (INLIBC(maddr)) {
                        // indent(0);
                        debug("* WARNING: strange write! rip=0x%x mnemonic=%s (0x%x+%s+%s*%d)"
                              " addr=0x%x\n", (int)r.rip, CH->mnem, CH->addr, CH->areg[0] ? CH->areg :
                              "none", CH->ireg[0] ? CH->ireg : "none", CH->sc, maddr);
                        goto exit_writecheck;
                    }
                }
            }
            // Local stack. Ignore.
            if (maddr < current->frend[current->fntop])
                goto exit_writecheck;

            be_silent = 1;
            add_wdescr(maddr, 1);
            be_silent = 0;

        }

    }

  exit_writecheck:

    if (current->nest >= 0 && !in_libc && !T_nomem) {
        struct changed *CH;

        CH = disassemble_address(op, 0);
        if (CH->addr || CH->areg[0] || CH->ireg[0]) {
            maddr = CH->addr;

            if (CH->areg[0]) {
                if (CH->areg[1] == 'a')
                    maddr += r.rax;
                else if (CH->areg[1] == 'c')
                    maddr += r.rcx;
                else if (CH->areg[1] == 'b' && CH->areg[2] == 'x')
                    maddr += r.rbx;
                else if (CH->areg[1] == 'd' && CH->areg[2] == 'x')
                    maddr += r.rdx;
                else if (CH->areg[1] == 'd' && CH->areg[2] == 'i')
                    maddr += r.rdi;
                else if (CH->areg[1] == 's' && CH->areg[2] == 'i')
                    maddr += r.rsi;
                else if (CH->areg[1] == 'b' && CH->areg[2] == 'p')
                    maddr += r.rbp;
                else
                    goto exit_readcheck;
            }

            if (CH->ireg[0]) {
                if (CH->ireg[1] == 'a')
                    maddr += r.rax * CH->sc;
                else if (CH->ireg[1] == 'c')
                    maddr += r.rcx * CH->sc;
                else if (CH->ireg[1] == 'b' && CH->ireg[2] == 'x')
                    maddr += r.rbx * CH->sc;
                else if (CH->ireg[1] == 'd' && CH->ireg[2] == 'x')
                    maddr += r.rdx * CH->sc;
                else if (CH->ireg[1] == 'd' && CH->ireg[2] == 'i')
                    maddr += r.rdi * CH->sc;
                else if (CH->ireg[1] == 's' && CH->ireg[2] == 'i')
                    maddr += r.rsi * CH->sc;
                else if (CH->ireg[1] == 'b' && CH->ireg[2] == 'p')
                    maddr += r.rbp * CH->sc;
                else
                    goto exit_readcheck;
            }
            // Hell knows where. Report.
            if (T_dostep)
                break_memread(maddr);

            if ((maddr >> 24) != STACKSEG) {
                if ((maddr >> 24) != CODESEG) {
                    // debug("codeseg %x maddr %x\n",CODESEG,(maddr >> 24));

                    if (!INLIBC(maddr) && maddr) {
                        // indent(0);
                        if (strcmp(CH->mnem, "lea"))
                            debug("* WARNING: strange read! rip=0x%x mnemonic=%s (0x%x+%s+%s*%d)"
                                  " addr=0x%x\n", (int)r.rip, CH->mnem, CH->addr, CH->areg[0] ? CH->areg :
                                  "none", CH->ireg[0] ? CH->ireg : "none", CH->sc, maddr);
                        goto exit_readcheck;
                    }
                }
            }
            // Local stack. Ignore.
            if (maddr < current->frend[current->fntop])
                goto exit_readcheck;

            be_silent = 1;
            add_wdescr(maddr, 0);
            be_silent = 0;

        }

    }

  exit_readcheck:

    if (current->getname) {

        // Ok, now some PLT magic. If we are in PLT and first JMP would
        // lead us into libc, we are following resolved name and we do not
        // have to care - just check rip in next cycle. Otherwise, the
        // symbol is not yet resolved, do not touch anything for a while.

        if ((!current->donottouch) && (AS_USHORT(op[0]) == 0x25ff)) {

            unsigned int dst = AS_UINT(op[2]);
            dst = ptrace(PTRACE_PEEKDATA, pid, dst, 0);
            if (INLIBC(dst))
                current->intercept = 1;
            current->donottouch = 1;

        }
        // This is _dl_runtime_resolve+16, our key to actual libcall
        // entry point if we go thru resolver. It is called from PLT if
        // lazy mapping is resolved for the first time.

        else if ((AS_UINT(op[0]) == 0x0487595a) && (AS_UINT(op[4]) == 0x0008c224))
            current->intercept = 4;

    }

}

/*********************************************************
 * A-ha, this is our single-step handler. The idea is to *
 * find any child to sync, if any left, to handle some   *
 * high-level stuff and to pass assembler-level analysis *
 * to handle_process().                                  *
 *********************************************************/

int me_do_stopped;
char skipwait;
int rcount;

void donothing(int x __attribute__ ((unused)))
{
}

void singlestep(void)
{
    int status = 0, ptr, sig = 0, i;

    if (T_dostep) {
        if (break_stopped && !me_do_stopped) {
            me_do_stopped = 1;
            while (!kill(pid, 0))
                if (!ptrace(PTRACE_GETREGS, pid, 0, &r))
                    break;
            if (first_getregs) {
                first_getregs = 0;
                if (is_static && (CODESEG != (r.rip >> 24)))
                    debug("***************************************************************\n"
                          "* WARNING: This is a binary, but initial rip is not in what I *\n"
                          "* consider a code segment. If you have difficulties tracing   *\n"
                          "* tracing this code, please consider using -X 0x%02llx option.    *\n"
                          "***************************************************************\n", (r.rip >> 24));
                break_sendentity();
            }
            fflush(0);
        }
        break_messenger();
        if (break_stopped)
            return;
        else
            me_do_stopped = 0;
    }

    if (!skipwait) {

      waitagain:

        alarm(1);

        pid = wait(&status);

        alarm(0);

        if (pid <= 0 && errno == EINTR) {
            if (T_dostep && current) {
                // Weh' loopin over da blocking signa'h, babe.
                if (current->syscalldone == 2) {
                    indent(0);
                    break_tellresumed();
                    current->syscalldone = 1;
                }
                pid = current->pid;
                blocking_syscall = current->syscall;
                break_messenger();
                fflush(0);
                // fprintf(stderr,"Had to wait at %x, sys %d blo %d sto %d con
                // %d\n",r.rip,current->syscall,
                // blocking_syscall,break_stopped,break_continuing);
            }
            goto waitagain;
        }

        if (pid <= 0) {
            test_leaks = 1;
            fatal("no more processes to trace", -1);
        }
        current = 0;
        for (i = 0; i < MAXCHILDREN; i++)
            if (pid == ps[i].pid) {
                current = &ps[i];
                break;
            }
        if (!current)
            fprintf(stderr, "DOH DOH [pid %d, ps[0] = %d]!\n", pid, ps[0].pid);
        if (!current)
            return;             // Go away, you do not exist.
        check_doret();

        if (WIFSTOPPED(status)) {
            sig = WSTOPSIG(status);
            if (sig == SIGTRAP)
                sig = 0;
            else if (sig == SIGSTOP)
                sig = 0;

            if (sig) {

                if (get_handler(sig)) {

                    if (T_noindent)
                        debug("SIGNAL %d (%s) - will be handled by 0x%x\n", sig, strsignal(sig), get_handler(sig));
                    else
                        debug("%d:-- SIGNAL %d (%s) - will be handled by 0x%x\n",
                              pid, sig, strsignal(sig), get_handler(sig));

                    caddr = get_handler(sig);

                    handle_fncall(1);

                    if (T_dostep)
                        break_signal(sig);

                } else {

                    if (T_noindent)
                        debug("SIGNAL %d (%s) - will not be handled\n", sig, strsignal(sig));
                    else
                        debug("%d:-- SIGNAL %d (%s) - will not be handled\n", pid, sig, strsignal(sig));

                    if (T_dostep)
                        break_signal(sig);

                }

            }

        }

    }
    // We found a syscall one instruction ago. Since then, PTRACE_SINGLESTEP
    // was issued to handle it. Now, we're most likely being stopped because
    // of the syscall, and should schedule syscall return in next
    // instruction (use syscalldone flag).

    if (!break_continuing) {
        if (current->syscalldone == 2) {
            if (rcount++ > 1) {
                current->syscalldone = 0;
                current->syscall = 0;
            }
        }
        if (current->syscalldone == 1) {
            ptrace(PTRACE_GETREGS, pid, 0, &r);
            // fprintf(stderr,"syscall is DONE at 0x%x [%d] ==
            // %d.\n",r.rip,current->syscall,r.rax);
            ret_syscall();

#define ERESTARTSYS     512

            if (T_dostep && break_stopped) {
                if (r.rax == -ERESTARTSYS)
                    break_tellwillresume(1);
                else
                    break_tellwillresume(0);
            }

            current->syscalldone = 2;
            rcount = 0;
        } else if (!current->syscalldone && current->syscall) {
            // fprintf(stderr,"syscall %d is set at 0x%x, setting
            // done.\n",current->syscall,r.rip);
            current->syscalldone = 1;
            sig = 0;
            goto justptrace;
        }
        handle_process();
    }

    if (!current)
        return;

    if (T_dostep) {
        skipwait = 0;
        if ((!in_libc) && (!break_continuing))
            if (!break_single()) {
                skipwait = 1;
                return;
            }
        if (should_be_stopped()) {
            skipwait = 1;
            return;
        }
        break_newline();
    }

    break_continuing = 0;

  justptrace:

    ptr = ptrace(PTRACE_SINGLESTEP, pid, 1, sig);

    if (ptr) {

        if (errno == ESRCH) {

            break_newline();

            debug("+++ Process %d ", pid);

            if (WIFSIGNALED(status))
                debug("killed by signal %d ", WTERMSIG(status));
            else if (WIFEXITED(status))
                debug("exited with code %d ", WEXITSTATUS(status));
            else
                debug("disappeared??? ");

            if (current->syscall) {
                // FIXME: hardcoded?!? more than 300+ for i386
                debug("in syscall %s (%d) ", scnames[current->syscall & 0xff], current->syscall);
            }

            debug("+++\n");

            if (!(current->fncalls || current->libcalls))
                if (current->ncalls)
                    debug("************************************************************\n"
                          "* Hmm, call me suspicious. I tried to skip libc prolog for *\n"
                          "* this application, but it seems to me I skipped way too   *\n"
                          "* much. Maybe this program is too smart for me? Maybe it   *\n"
                          "* was compiled in some exotic place? Consider using -s     *\n"
                          "* option for now, and contact my author!                   *\n"
                          "************************************************************\n");
        } else
            fatal("PTRACE_SINGLESTEP failed", errno);

        remove_process();

    } else
        current->cycles++;

}

/*****************************************************
 * We probably want to determine if given executable *
 * is or dynamic. Hey, that'll do!            *
 *****************************************************/

int am_i_static(const int fd)
{
    int i;
    lseek(fd, 0x51, SEEK_SET);
    read(fd, &i, 4);
    if (i == 0x03000000)
        return 0;
    return 1;
}

/*********************************************
 * Check for binary location, emulate execvp *
 *********************************************/

void check_binary(const char *path, unsigned char script)
{
    char *p;
    char *res;
    char tmpbuf[MPS + 2];
    char tmpp[MPS + 2];
    int f;

    bzero(tmpbuf, MPS + 2);
    bzero(tmpp, MPS + 2);

    if (strchr(path, '/')) {
        strncpy(tmpbuf, path, MPS);
        f = open(tmpbuf, O_RDONLY);
        if (f < 0)
            return;
        read(f, tmpbuf, 2);

        // Handle shell scripts.
        if (tmpbuf[0] == '#' && tmpbuf[1] == '!') {
            char *x;
            int i;
            if (script) {
                close(f);
                return;
            }                   // Looping!
            if ((i = read(f, tmpbuf, MPS)) <= 0) {
                close(f);
                return;
            }
            tmpbuf[i] = 0;
            x = strchr(tmpbuf, '\n');
            if (!x) {
                close(f);
                return;
            }
            *x = 0;
            close(f);
            check_binary(tmpbuf, 1);
            return;
        }

        is_static = am_i_static(f);
        close(f);
        return;
    }

    if (!getenv("PATH"))
        return;
    strncpy(tmpp, getenv("PATH"), MPS);

    p = tmpp;
    while ((res = strtok(p, ":"))) {
        p = 0;
        strcpy(tmpbuf, res);
        nappend(tmpbuf, "/", MPS);
        nappend(tmpbuf, path, MPS);
        f = open(tmpbuf, O_RDONLY);
        if (f < 0)
            continue;

        // Handle shell scripts.
        if (tmpbuf[0] == '#' && tmpbuf[1] == '!') {
            char *x;
            int i;
            if (script) {
                close(f);
                return;
            }                   // Looping!
            if ((i = read(f, tmpbuf, MPS)) <= 0) {
                close(f);
                return;
            }
            tmpbuf[i] = 0;
            x = strchr(tmpbuf, '\n');
            if (!x) {
                close(f);
                return;
            }
            *x = 0;
            close(f);
            check_binary(tmpbuf, 1);
            return;
        }

        is_static = am_i_static(f);
        close(f);
        return;
    }

}

/*******************************
 * Check if libc mapping is OK *
 *******************************/

void addr_check(void)
{
    void *x;
    unsigned long int y;
    x = dlopen("/lib/libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
    if (!x)
        return;                 // Huh?
    y = (unsigned long int)dlsym(x, "open");
    dlclose(x);
    if (!INLIBC(y)) {
        debug("***********************************************************\n"
              "* During installation, I have determined that libraries   *\n"
              "* in your system are mapped at 0x%01xnnnnnnn. Now, I've just *\n"
              "* performed simple test to discover this is no longer     *\n"
              "* true: library function 'open' is mapped at 0x%08lx.  *\n"
              "* It might be because you've upgraded your kernel or have *\n"
              "* some security-enhancing random address mapping feature. *\n"
              "* In first case, all you have to do is to recompile me.   *\n"
              "* In second case, I'm afraid I can't work with dynamic   *\n"
              "* applications. I'm terribly sorry.                       *\n"
              "***********************************************************\n", LIBCSEG, y);
        fatal("libc mapping problems", -1);
    }
#ifdef NOPROLOG
    if (!innest)
        debug("*************************************************************\n"
              "* You have to run me with -s (no prolog detection) option.  *\n"
              "* This is because I was not able to recognize your libc     *\n"
              "* prolog at the time of compilation, and I cannot detect it *\n"
              "* automatically. I am handicapped, please try recompiling   *\n"
              "* me, read warnings and eventually contact the author!      *\n"
              "*************************************************************\n");
    fatal("dynamic mode disabled", -1);
#endif /* NOPROLOG */

}

/******************
 * Burn in flames *
 ******************/

void dienow(int x __attribute__ ((unused)))
{
    fatal("interrupted", -2);
}

/*********************
 * Usage information *
 *********************/

void usage(void)
{
    debug("\n"
          "Usage: fenris [ -o file ] [ -E PAR=VAL ] [ -u user ] [ -L dbase ] [ -R a:b ]\n"
          "              [ -t num ] [ -P i:a:v ] [ -W path ] [ -sdiGCSfFmxpAyqe ] [ -X pr ]\n"
          "              program [ params... ]\n"
          "       -o file        - write trace output to file (default: stderr)\n"
          "       -u user        - run program as user (you need root to do that)\n"
          "       -E PAR=VAL     - add PAR to the environment (e.g. LD_PRELOAD)\n"
          "       -L dbase       - load additional fingerprints database\n"
          "       -t num         - main is num rets away from ctors (default: 2)\n"
          "       -R [a]:[b]     - start trace when rip=a and/xor stop when rip=b\n"
          "       -P [i:]a:v     - replace byte at address a with v [when rip=i]\n"
          "       -W path        - run in debugger mode; listen on unix socket 'path'\n"
          "       -X seg         - use X as a code segment prefix (first byte value)\n"
          "       -s             - disable libc prolog detection (not recommended)\n"
          "       -y             - report memory access immediately\n"
          "       -C             - inhibit tracing conditional expressions\n"
          "       -S             - inhibit resolving library symbols\n"
          "       -f             - trace child processes after fork() or vfork()\n"
          "       -d             - do not describe function parameters\n"
          "       -F             - do not fingerprint functions (binaries)\n"
          "       -m             - do not trace memory writes\n"
          "       -i             - do not indent\n"
          "       -x             - do not try to skip libc outro (no exit from main)\n"
          "       -p             - prefix every line with rip\n"
          "       -A             - force return value on all functions\n"
          "       -q             - don't report last line to debugger (only with -W)\n"
          "       -G             - go away! Do not do any high-level analysis\n"
          "       -e             - trace new code after execve()\n\n");
    exit(1);
}

/*********************
 * Main entry point. *
 *********************/

int main(const int argc, const char **argv)
{
    FILE *t = stderr;
    char *outbuf;
    char opt;
    int dummy = 1;

    ostream = stderr;

    allocs_set_error_handler((allocs_error_handler_ftype) fatal);

    assert((MAXNEST % 2) == 0);
    signal(SIGUSR1, exit);
    signal(SIGTRAP, SIG_IGN);

    signal(SIGSEGV, segfault);
    signal(SIGILL, segfault);
    signal(SIGBUS, segfault);
    signal(SIGFPE, segfault);
    signal(SIGPIPE, pipefault);
    signal(SIGINT, dienow);
    signal(SIGTERM, dienow);

    STACKSEG = ((unsigned long int)(&dummy) >> 24);
    CODESEG = ((unsigned long int)(main) >> 24);
    running_under_ncaegir = getenv("NCAEGIR_PIPE");
    unsetenv("NCAEGIR_PIPE");
    unsetenv("NCAEGIR_SOCK");
    unsetenv("NCAEGIR_CMD");

    if (running_under_ncaegir && !getenv("DISPLAY")) {

        debug(RED "Note: this is a program I/O screen. If you are not automatically taken\n"
              "to the debugger screen, press ctrl+a, n or another screen switching\n"
              "sequence configured for your 'screen' utility. " NOR "\n\n");
    }

    debug("fenris %s ( %s %ld) - program execution path analysis tool\n"
          "Brought to you by Michal Zalewski <lcamtuf@coredump.cx>\n", VERSION, BUILD, sizeof(struct fenris_process));

    while ((opt = getopt(argc, (void *)argv, "+sCR:SidAGo:fmFpyqt:xX:eW:E:u:L:P:")) != EOF)
        switch (opt) {

            case 'P':{
                    unsigned int ip = 0, ad, va;
                    if (sscanf(optarg, "%i:%i:%i", &ip, &ad, &va) != 3) {
                        ip = 0;
                        if (sscanf(optarg, "%i:%i", &ad, &va) != 2)
                            fatal("malformed -P option", -1);
                    }
                    if (va > 255)
                        fatal("-P with excessive last param", -1);
                    reptable[reptop].ip = ip;
                    reptable[reptop].ad = ad;
                    reptable[reptop].va = va;
                    reptop++;
                    if (reptop >= MAXREP)
                        fatal("too many -P options (change config.h)", 0);
                }
                break;

            case 't':
                T_atret = atoi(optarg);
                break;

            case 'G':
                T_goaway = 1;
                break;

            case 'W':
                T_dostep = optarg;
                break;

            case 'q':
                T_nolast = 1;
                break;

            case 'X':
                sscanf(optarg, "%i", &CODESEG);
                if (CODESEG > 0xff)
                    fatal("codeseg has to be a single byte value", -1);
                break;

            case 's':
                innest = 0;
                nonstd = 1;
                break;

            case 'y':
                T_wnow = 1;
                nonstd = 1;
                break;

            case 'R':
                if (!strchr(optarg, ':'))
                    fatal("-R needs :", -1);
                if (strchr(optarg, ':') == optarg)
                    sscanf(optarg, ":%x", &stop_rip);
                else
                    sscanf(optarg, "%x:%x", &start_rip, &stop_rip);
                break;

            case 'F':
                T_nosig = 1;
                nonstd = 1;
                break;

            case 'A':
                T_alwaysret = 1;
                break;

            case 'C':
                T_nocnd = 1;
                nonstd = 1;
                break;

            case 'S':
                T_nosym = 1;
                nonstd = 1;
                break;

            case 'p':
                T_addip = 1;
                break;

            case 'o':
                if (optarg[0] == '#') {
                    t = fopen(optarg + 1, "w");
                    if (!t)
                        fatal("cannot open output file", errno);
                    outbuf = malloc(SMALLOUT);
                    setbuffer(t, outbuf, SMALLOUT);
                } else {
                    t = fopen(optarg, "w");
                    if (!t)
                        fatal("cannot open output file", errno);
                    outbuf = malloc(OUTBUF);
                    setbuffer(t, outbuf, OUTBUF);
                }
                break;

            case 'f':
                T_forks = 1;
                break;

            case 'i':
                T_noindent = 1;
                nonstd = 1;
                break;

            case 'd':
                T_nodesc = 1;
                nonstd = 1;
                break;

            case 'm':
                T_nomem = 1;
                nonstd = 1;
                break;

            case 'e':
                T_execs = 1;
                break;

            case 'L':
                if (load_fnbase(optarg) == -1)
                    debug("* WARNING: cannot load '%s' fingerprints database.\n", optarg);
                break;

            case 'E':
                putenv(optarg);
                break;

            case 'x':
                T_noskip = 1;
                break;

            case 'u':{
                    struct passwd *p = getpwnam(optarg);
                    if (!p)
                        fatal("no such user", -1);
                    runasuid = p->pw_uid;
                    runasgid = p->pw_gid;
                    runasuser = strdup(optarg);
                }
                break;

            default:
                usage();

        }

    if (argc - optind < 1)
        usage();

    if (T_dostep && T_forks) {
        debug("*******************************************************************\n"
              "* You have chosen to run Fenris in the interactive debugger mode. *\n"
              "* This mode does not support tracing multiple processes, and thus *\n"
              "* it is impossible to trace after fork()s. You can, however, work *\n"
              "* around this limitation - see the documentation for details.     *\n"
              "*******************************************************************\n");
        fatal("-W and -f are mutually exclusive", -1);
    }

    if (T_nolast && !T_dostep) {
        fatal("-q has no use without -W", -1);
    }

    if (!T_dostep && T_goaway) {
        fatal("I will go away only if you use -W", -1);
    }

    if (T_dostep) {
        break_listen(T_dostep, &argv[optind - 1]);
        break_stopped = 1;
    }

    if (!T_nosig)
        if (load_fnbase(FN_DBASE) == -1)
            debug("* WARNING: cannot load '%s' fingerprints database.\n", FN_DBASE);

    ostream = t;

    if (ostream != stderr) {
        debug("<<-- fenris [%s] " VERSION " -->>\n", nonstd ? "CSTM" : "STD");
        fflush(0);
    }

    check_binary(argv[optind], 0);
    if (!is_static)
        addr_check();

    bfd_init();
    add_process(start_child(&argv[optind - 1]));

    {
        struct sigaction a;
        bzero(&a, sizeof(a));
        a.sa_handler = donothing;
        sigaction(SIGALRM, &a, 0);
    }

    while (1)
        singlestep();

    debug(">> What kind of Turing machine are you, anyway?!\n");
    return 0;

}
