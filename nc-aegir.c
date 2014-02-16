/*
    nc-aegir - interactive debugging GUI for fenris
    -----------------------------------------------

    Copyright (C) 2002 Andrzej Szombierski <anszom@v-lo.krakow.pl>
    Based on Aegir by Michal Zalewski <lcamtuf@coredump.cx>
    [ I added some bugs later -- Michal ]

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

#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <termios.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <ncurses.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#define ENVPIPE "NCAEGIR_PIPE"
#define ENVSOCK "NCAEGIR_SOCK"
#define ENVCMD  "NCAEGIR_CMD"

#define regs_color      (COLOR_PAIR(1) | A_BOLD)
#define running_color   (COLOR_PAIR(2) | A_BOLD | A_BLINK)
#define data_color      (COLOR_PAIR(3) | A_BOLD)
#define fenris_color    (COLOR_PAIR(4) | A_BOLD)
#define prompt_color    (def | A_BOLD)
#define fatal_color     (def | A_BOLD)
#define cyan_color      (COLOR_PAIR(5) | A_BOLD)
#define cblink_color    (COLOR_PAIR(5) | A_BOLD | A_BLINK)
#define code_color      (COLOR_PAIR(6))

#define def     0

// hardcoded window heights
#define WD      4
#define WC      6
#define WF      6
#define WA      (LINES-(WC+WD+WF+3))

int doingstop;
int syscnum;

void inline do_prompt(int n);
void refresh_all(int t);

WINDOW *Waegir, *Wregs, *Wdata, *Winput, *Wstatus, *Wcode, *Wfenris;

#ifndef UNIX_PATH_MAX           /* max unix socket name length */
#define UNIX_PATH_MAX   108
#endif

#include "config.h"
#include "fdebug.h"
#include "libdisasm/opcodes2/opdis.h"

int stopped;
int please_disass;

/******************************************************************************/

void clean_exit(int n);
char * reg_mem_code_update();
void my_wprintw(WINDOW * w, char * fmt, ...);
void my_waddstr(WINDOW * w, char * str);

unsigned int wdata_addr;
unsigned int Wcode_addr;

#include "rstree.h"

//#define debug(x...)     fprintf(stderr,x)
#define debug(x...)     my_wprintw(Waegir,x)

#define pfatal(y)       { if (y) debug("FATAL: %s (%s)\n",y,sys_errlist[errno]); clean_exit(1); }
#define fatal(x)        { wattrset(Waegir,fatal_color); debug("FATAL: %s\n",x); clean_exit(1); }

#include "common.h"

/******************************************************************************/

const static char* scnames[256]= {
    0,
#include "scnames.h"
    0
};

#define MAXMYSIG 31
const static char* my_siglist[] = { "none", "sighup", "sigint", "sigquit",
    "sigill", "sigtrap", "sigabrt", "sigbus", "sigfpe", "sigkill", "sigusr1",
    "sigsegv", "sigusr2", "sigpipe", "sigalrm", "sigterm", "sigchld", "sigcont",
    "sigstop", "sigtstp", "sigttin", "sigttou", "sigurg", "sigxcpu", "sigxfsz",
    "sigvtalrm", "sigprof", "sigwinch", "sigio", "sigpwr", "sigsys", 0 };

/******************************************************************************/

struct aegir_cmd {
    char* cmd;
    void (*handler)(char* param);
    char* help;
};

extern struct aegir_cmd cmd[];

struct Wcode_info {
    RSTree tree;                /* stores disassembled addresses
                                 * key-> opcode addr
                                 * val-> opcode size
                                 */

    RSNode top_node;    /* Wcode topmost opcode (tree node)
                         */

    unsigned int cur_addr;      /* highlighted opcode addr */
} Wcode_info;

/******************************************************************************/

// For sscanf hack. Blame libc authors.

unsigned long long l1, l2;

#define LC(x) { \
    if (x > 0xffffffff) { debug("Value out of range.\n"); \
        return; } \
}

/******************************************************************************/

void* send_message(int mtype,void* data,void* store);

static unsigned int sd;

static void connect_to_fenris(char* where) {
    struct sockaddr_un sun;

    debug("[+] Connecting to Fenris at %s...\n",where);

    if ((sd = socket (AF_LOCAL, SOCK_STREAM, 0))<0) {
        pfatal("cannot create a socket");
        clean_exit(1);
    }

    sun.sun_family = AF_LOCAL;
    strncpy (sun.sun_path, where, UNIX_PATH_MAX);
    if (connect (sd, (struct sockaddr*)&sun,sizeof (sun))) {
        pfatal("cannot connect to Fenris socket");
        clean_exit(1);
    }

    debug("[+] Trying to send \"hello\" message...\n");
    send_message(DMSG_FOO,0,0);
    debug("[*] Response ok, connection established.\n\n");

}

/******************************************************************************/

static char str_buf[MAXFENT];

static char* get_string_sock(int sock) {
    int len=0;
    while (1) {
        if (read(sock,str_buf+len,1)!=1) fatal("short read in get_string_sock from Fenris");

        if (!str_buf[len])return str_buf;

        if(++len >= sizeof(str_buf)-2)
            fatal("string from Fenris is of excessive length");
    }
    fatal("Another broken Turing machine. Rhubarb.");
}

static int get_dword_sock(int sock) {
    int ret=0;
    if (read(sock,&ret,4)!=4)
        fatal("short read in get_dword_sock in Fenris");
    return ret;
}

static char msg_data[MAXFENT];
void* send_message(int mtype,void* data,void* store) {
    struct dmsg_header x;
    int dlen=0;
    if (!store) store=msg_data;
    switch (mtype) {

        case DMSG_NOMESSAGE: break; /* don't send, just read */

        case DMSG_RWATCH: case DMSG_WWATCH: case DMSG_SETMEM:
        case DMSG_GETMEM: dlen=8; break;

        case DMSG_ABREAK: case DMSG_SBREAK:   case DMSG_STEP:
        case DMSG_TORET:  case DMSG_FPRINT:   case DMSG_DEL:
        case DMSG_IBREAK: case DMSG_DESCADDR: case DMSG_DESCFD:
        case DMSG_GETNAME: dlen=4; break;

        case DMSG_GETADDR: dlen=strlen(data)+1; break;
        case DMSG_SETREGS: dlen=sizeof(struct user_regs_struct); break;

        case DMSG_GETREGS: case DMSG_GETMAP:    case DMSG_FDMAP: case DMSG_FNLIST:
        case DMSG_SIGNALS: case DMSG_TOLIBCALL: case DMSG_TOSYSCALL:
        case DMSG_TOLOCALCALL: case DMSG_TOLOWERNEST: case DMSG_GETBACK:
        case DMSG_RUN: case DMSG_TONEXT: case DMSG_STOP: case DMSG_HALT:
        case DMSG_LISTBREAK: case DMSG_KILL: case DMSG_DYNAMIC:
        case DMSG_FOO:  dlen=0; break;

        default: fatal("unknown message type in send_message");

    }

    if (mtype!=DMSG_NOMESSAGE) {
        if (dlen && !data) fatal("message needs data but data is NULL");
        x.magic1=DMSG_MAGIC1;
        x.magic2=DMSG_MAGIC2;
        x.type=mtype;

        errno=0;
        if (write(sd,&x,sizeof(x))<=0)
            fatal("connection to Fenris dropped (tried to send message header)");

        if (dlen)
            if (write(sd,data,dlen)<=0)
                fatal("connection to Fenris dropped (tried to send message data)");

    }

    while(1){
        int a,b;
        static int prevstopped=0;
        errno=0;
        bzero(&x,sizeof(x));

        if (read(sd,&x,sizeof(x))!=sizeof(x))
            fatal("disconnected from Fenris");

        if (x.magic1 != DMSG_MAGIC1) fatal("incorrect magic1 from Fenris");
        if (x.magic2 != DMSG_MAGIC2) fatal("incorrect magic2 from Fenris");

        stopped=!(x.code_running);
        syscnum=x.code_running;

        wmove(Wstatus,0,1);
        wattrset(Wstatus,stopped? def : running_color);
        waddch(Wstatus,stopped?'s':'R');

        if(stopped && !prevstopped) please_disass=1;
        prevstopped=stopped;

        if (x.type == DMSG_ASYNC) {
            char* xx=get_string_sock(sd);
            debug("%s",xx);     //FIXME
            if(mtype == DMSG_NOMESSAGE)break;
            continue;
        }

        if (x.type != DMSG_REPLY) fatal("invalid message type from Fenris");

        switch (mtype) {
            // If we didn't send any message, we don't want replies.
            case DMSG_NOMESSAGE:
                fatal("no sync response expected for DMSG_NOMESSAGE"); break;
                // GETMEM returns dword:length and raw data

            case DMSG_GETMEM:
                a=get_dword_sock(sd);
                if (a<0 || a>=MAXFENT-4) fatal("excessive data length in DMSG_GETMEM");
                memcpy(store,&a,4);
                b=0;
                while (b<a) {
                    int inc;
                    inc=read(sd,&((char*)store)[4+b],a-b);
                    if (inc<=0) fatal("short read on DMSG_GETMEM");
                    b+=inc;
                }
                break;

                // Most requests return strings
            case DMSG_GETBACK:
            case DMSG_STEP:
            case DMSG_TORET:
            case DMSG_TOLIBCALL:
            case DMSG_TOSYSCALL:
            case DMSG_TOLOCALCALL:
            case DMSG_GETNAME:
            case DMSG_RWATCH:
            case DMSG_WWATCH:
            case DMSG_TOLOWERNEST:
            case DMSG_DESCADDR:
            case DMSG_DESCFD:
            case DMSG_STOP:
            case DMSG_HALT:
            case DMSG_FPRINT:
            case DMSG_SETMEM:
            case DMSG_LISTBREAK:
            case DMSG_DEL:
            case DMSG_DYNAMIC:
            case DMSG_SETREGS:
            case DMSG_ABREAK:
            case DMSG_GETMAP:
            case DMSG_FDMAP:
            case DMSG_FNLIST:
            case DMSG_RUN:
            case DMSG_SIGNALS:
            case DMSG_KILL:
            case DMSG_SBREAK:
            case DMSG_TONEXT:
            case DMSG_IBREAK:
                strcpy(store,get_string_sock(sd));
                break;

                // GETADDR returns dword
            case DMSG_GETADDR:
                a=get_dword_sock(sd);
                memcpy(store,&a,4);
                break;

                // GETREGS returns user_regs_struct
            case DMSG_GETREGS:
                if (read(sd,store,sizeof(struct user_regs_struct))!=
                        sizeof(struct user_regs_struct))
                    fatal("short read on DMSG_RETREGS");
                break;

                // Empty.
            case DMSG_FOO:  break;

                            // Catch whatever I missed...
            default: fatal("implementation error in send_message");
        }
        break;
    }
    return store;
}

/******************************************************************************/

// "load" handler
static void load_module(char* what) {
    void* x;
    void (*modinit)(void);

    if (!what) {
        debug("You have to provide module name.\n");
        return;
    }

    x=dlopen(what,RTLD_LAZY|RTLD_GLOBAL);

    if (!x) {
        debug("Cannot open module %s: %s\n",what,dlerror());
        return;
    }

    modinit=dlsym(x,"aegir_module_init");

    if (!modinit) {
        debug("Error: this module does not have 'aegir_module_init' export.\n");
        dlclose(x);
        return;
    }

    modinit();
    debug("Module %s loaded.\n",what);

}

// "help" handler
static void display_help(char* param) {
    int q=0;
    while (cmd[q].cmd) {
        char command[512];
        char *start;
        if (!cmd[q].help) { q++; continue; }
        command[sizeof(command)-1]=0;

        if (!strchr(cmd[q].help,':')) {
            strcpy(command,cmd[q].cmd);
            start=cmd[q].help;
        } else {
            strncpy(command,cmd[q].help,sizeof(command)-1);
            if (!strchr(command,':')) fatal("Are you insane?");
            *strchr(command,':')=0;
            start=strchr(cmd[q].help,':')+1;
            while (*start && isspace(*start)) start++;
        }
        debug("%-15s - %s\n",command,start);
        q++;
    }
    debug("\nFor additional help, please refer to debugger's documentation.\n");
}

// "quit" handler
static void handle_quit(char* param) {
    if (!param) {
        debug("Use 'quit yes' or 'q y' if you really mean it.\n");
        return;
    }
    clean_exit(0);
}

// "exec" handler
static void exec_cmd(char* param) {
    if (!param) {
        debug("You have to provide a command to be executed.\n");
        return;
    }
    endwin();
    system(param);

    refresh_all(1);
}

// custom fprintf routine, called indirectly from opdis.c
static int nc_fprintf(FILE *stream, char *format, ...)
{
    va_list args;

    va_start(args, format);
    vw_printw( (WINDOW*)stream, format, args);
    va_end(args);
    return 0;
}

// "disass" handler
static void do_disass(char* param) {
    unsigned int st,len;
    char* mem;
    unsigned int par[2];
    int retlen;

    if (!param) {
        struct user_regs_struct* x;
        x=(void*)send_message(DMSG_GETREGS,0,0);
        st=x->eip;
        len=0;
    } else {
        if (strchr(param,' ')) {
            if (sscanf(param,"%Li %Li",&l1,&l2)!=2) {
                debug("Numeric parameters required.\n");
                return;
            }
            st=l1;len=l2;
            LC(l1); LC(l2);

            if (len<0) {
                debug("Empty range provided.\n");
                return;
            }
        } else {
            if (sscanf(param,"%Li",&l1)!=1) {
                debug("The parameter needs to be an address.\n");
                return;
            }
            st=l1;
            len=0;
            LC(l1);
            Wcode_addr=l1;
            reg_mem_code_update();
        }
    }

    if (len > MAXFENT-30) {
        debug("You exceeded the maximum memory size per single request.\n");
        len=MAXFENT-30;
    }

    par[0]=st; par[1]=st+len+16;
    mem=send_message(DMSG_GETMEM,(char*)&par,0);
    retlen=*((unsigned int*)mem);
    if (retlen<=0) {
        debug("Unable to access memory at 0x%x.\n",st);
        return;
    }
    {
        debug("\n");
        opdis_disass( (FILE*)Waegir, &mem[4], st, len>retlen ? retlen : len);
    }
    if (retlen<len)
        debug("Truncated - unable to access memory past 0x%x.\n",st+retlen);
}

// Describe addresses in disassembly. Called from opdis.c.

char descbuf[MAXFENT];

char* describe_address(unsigned int addr) {
    return send_message(DMSG_GETNAME,(char*)&addr,descbuf);
}

static char * wmemdump(WINDOW *w, unsigned int st, unsigned int len,char verb)
{
    char* mem;
    int retlen;
    int caddr;

    unsigned int par[2]={st,st+len};
    mem=send_message(DMSG_GETMEM,(char*)&par,0);
    retlen=*((unsigned int*)mem);
    mem+=4;
    if (retlen<=0) {
        if (!verb) return 0;
        my_wprintw(Waegir,"Unable to access memory at 0x%x.\n",st);
        return 0;
    }
    if (!verb) werase(Wdata);

    if (retlen>len) retlen=len;

    caddr=0;
    while (caddr<retlen) {
        int i;
        int rem;
        rem=retlen-caddr;
        if (rem>16) rem=16;
        my_wprintw(w,"%08x: ",st+caddr);

        for (i=0;i<16;i++) {
            if (i && !(i % 4)) my_wprintw(w," ");
            if (i<rem)
                my_wprintw(w,"%02x ",(unsigned char)mem[caddr+i]);
            else
                my_waddstr(w,"   ");
        }

        my_waddstr(w,"| ");
        for (i=0;i<rem;i++) waddch(w,isprint(mem[caddr+i])?mem[caddr+i]:'.');
        my_waddstr(w,"\n");
        caddr+=16;
    }

    if (retlen<len) {
        my_wprintw(/*Waegir*/w,"Truncated - unable to access memory past 0x%x.\n",st+retlen);
    }
    return mem;
}

// "x" handler
static void do_memdump(char* param) {
    unsigned int st,len;

    if (!param) {
        debug("One or two parameters required.\n");
        return;
    } else {
        if (strchr(param,' ')) {
            if (sscanf(param,"%Li %Li",&l1,&l2)!=2) {
                debug("Numeric parameters required.\n");
                return;
            }
            st=l1;len=l2;
            LC(l1); LC(l2);

            if (len<0) {
                debug("Empty range provided.\n");
                return;
            }
        } else {
            if (sscanf(param,"%Li",&l1)!=1) {
                debug("Numeric parameter required.\n");
                return;
            }
            //      st=l1;
            LC(l1);
            st=wdata_addr;
            wdata_addr=l1;
            len=16*4;
            if(!reg_mem_code_update()){
                wdata_addr=st;
                reg_mem_code_update();
            }
            return;
        }
    }

    if (len > MAXFENT-20) {
        debug("You exceeded the maximum memory size per single request.\n");
        len=MAXFENT-20;
    }

    if (st > st + len) {
        debug("Illegal combination of start address and length.\n");
        return;
    }

    wmemdump(Waegir,st,len,1);

}

static void do_rwatch(char* param) {
    char* mem;
    unsigned int par[2];

    if (!param) {
        debug("Two parameters required.\n");
        return;
    } else {
        if (sscanf(param,"%Li %Li",&l1,&l2)!=2) {
            debug("Two numeric parameters required.\n");
            return;
        }
        par[0]=l1;par[1]=l2;
        LC(l1); LC(l2);

        if (par[0] > par[1]) {
            debug("Empty range provided.\n");
            return;
        }
    }

    mem=send_message(DMSG_RWATCH,(char*)&par,0);
    debug("%s",mem);
}

FILE* extralog;

static void do_log(char* param) {
    FILE* tmp;

    if (!param && extralog) {
        debug("Logging stopped.\n");
        fclose(extralog); extralog=0;
        return;
    }

    if (!param && !extralog) { debug("Log never started.\n"); return; }

    if (param && extralog) {
        debug("Closing old log...\n");
        fclose(extralog); extralog=0;
    }

    tmp=fopen(param,"w");

    if (!tmp) {
        debug("Cannot create log file '%s'.\n",param);
        return;
    }

    extralog=tmp;

    debug("New log '%s' initiated.\n",param);

}

static void do_logappend(char* data) {
    if (!extralog) return;
    fwrite(data,strlen(data),1,extralog);
}

static void do_wwatch(char* param) {
    char* mem;
    unsigned int par[2];

    if (!param) {
        debug("Two parameters required.\n");
        return;
    } else {
        if (sscanf(param,"%Li %Li",&l1,&l2)!=2) {
            debug("Two numeric parameters required.\n");
            return;
        }
        par[0]=l1;par[1]=l2;
        LC(l1); LC(l2);

        if (par[0] > par[1]) {
            debug("Empty range provided.\n");
            return;
        }
    }

    mem=send_message(DMSG_WWATCH,(char*)&par,0);
    debug("%s",mem);
}

// "x" handler
static void do_setmem(char* param) {
    char* res;
    unsigned int par[2];

    if (!param) {
        debug("Two parameters required.\n");
        return;
    } else {
        if (sscanf(param,"%Li %Li",&l1,&l2)!=2) {
            debug("Numeric parameters required.\n");
            return;
        }
        par[0]=l1;par[1]=l2;
        LC(l1); LC(l2);

    }

    res=send_message(DMSG_SETMEM,(char*)&par,0);
    debug("%s",res);

}

// "y" handler
static void do_strdump(char* param) {
    unsigned int st;
    char* mem;
    unsigned int par[2];
    int retlen;
    int i;

    if (!param) {
        debug("Parameter required.\n");
        return;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            debug("Numeric parameter required.\n");
            return;
        }
        st=l1;
        LC(l1);

    }

    par[0]=st; par[1]=st+MAXYSTR;

    mem=send_message(DMSG_GETMEM,(char*)&par,0);

    retlen=*((unsigned int*)mem);

    if (retlen<=0) {
        debug("Unable to access memory at 0x%x.\n",st);
        return;
    }

    debug("%08x: \"",st);

    for (i=0;i<retlen;i++) {
        if (!mem[4+i]) break;
        if (isprint(mem[4+i]) && mem[4+i]!='"') debug("%c",mem[4+i]);
        else debug("\\x%02x",(unsigned char)mem[4+i]);
    }

    if (i==retlen) {
        if (retlen<MAXYSTR) debug("\"... <read past accessible memory>\n");
        else debug("\"...\n");
    } else debug("\"\n");

}

static void do_regs(char* param) {
    struct user_regs_struct* x;
    x=(void*)send_message(DMSG_GETREGS,0,0);

    debug("eax \t0x%08x\t %d\n",x->eax,x->eax);
    debug("ebx \t0x%08x\t %d\n",x->ebx,x->ebx);
    debug("ecx \t0x%08x\t %d\n",x->ecx,x->ecx);
    debug("edx \t0x%08x\t %d\n",x->edx,x->edx);
    debug("esi \t0x%08x\t %d\n",x->esi,x->esi);
    debug("edi \t0x%08x\t %d\n",x->edi,x->edi);
    debug("ebp \t0x%08x\t %d\n",x->ebp,x->ebp);
    debug("esp \t0x%08x\t %d\n",x->esp,x->esp);
    debug("eip \t0x%08x\t %d\n",x->eip,x->eip);
    debug("eflags \t0x%08x\t 0%o\n",x->eflags,x->eflags);
    debug("ds \t0x%x\n",x->xds);
    debug("es \t0x%x\n",x->xes);
    debug("fs \t0x%x\n",x->xfs);
    debug("gs \t0x%x\n",x->xgs);
    debug("cs \t0x%x\n",x->xes);
    debug("ss \t0x%x\n",x->xss);

}

static void do_setreg(char* param) {
    char* ww;
    struct user_regs_struct x;
    char regname[128];
    int val;

    if (!param) {
        debug("Parameters required.\n");
        return;
    }

    if (sscanf(param,"%s %Li",regname,&l1)!=2) {
        debug("Two parameters, register name and numeric value, required.\n");
        return;
    }
    LC(l1);
    val=l1;

    send_message(DMSG_GETREGS,0,&x);

    if (!strcasecmp("eax",regname)) {
        debug("Changing %s from 0x%x to 0x%x...\n",regname,x.eax,val);
        x.eax=val;
    } else

        if (!strcasecmp("ebx",regname)) {
            debug("Changing %s from 0x%x to 0x%x...\n",regname,x.ebx,val);
            x.ebx=val;
        } else

            if (!strcasecmp("ecx",regname)) {
                debug("Changing %s from 0x%x to 0x%x...\n",regname,x.ecx,val);
                x.ecx=val;
            } else

                if (!strcasecmp("edx",regname)) {
                    debug("Changing %s from 0x%x to 0x%x...\n",regname,x.edx,val);
                    x.edx=val;
                } else

                    if (!strcasecmp("esi",regname)) {
                        debug("Changing %s from 0x%x to 0x%x...\n",regname,x.esi,val);
                        x.esi=val;
                    } else

                        if (!strcasecmp("edi",regname)) {
                            debug("Changing %s from 0x%x to 0x%x...\n",regname,x.edi,val);
                            x.edi=val;
                        } else

                            if (!strcasecmp("esp",regname)) {
                                debug("Changing %s from 0x%x to 0x%x...\n",regname,x.esp,val);
                                x.esp=val;
                            } else

                                if (!strcasecmp("eip",regname)) {
                                    debug("Changing %s from 0x%x to 0x%x...\n",regname,x.eip,val);
                                    debug("Note: modifying eip is the best way to trash Fenris. Act wisely.\n");
                                    x.eip=val;
                                } else

                                    if (!strcasecmp("ebp",regname)) {
                                        debug("Changing %s from 0x%x to 0x%x...\n",regname,x.ebp,val);
                                        x.ebp=val;
                                    } else

                                        if (!strcasecmp("eflags",regname)) {
                                            debug("Changing %s from 0x%x to 0x%x...\n",regname,x.eflags,val);
                                            x.eflags=val;
                                        } else

                                            if (!strcasecmp("ds",regname)) {
                                                debug("Changing %s from 0x%x to 0x%x...\n",regname,x.xds,val);
                                                x.xds=val;
                                            } else

                                                if (!strcasecmp("es",regname)) {
                                                    debug("Changing %s from 0x%x to 0x%x...\n",regname,x.xes,val);
                                                    x.xes=val;
                                                } else

                                                    if (!strcasecmp("fs",regname)) {
                                                        debug("Changing %s from 0x%x to 0x%x...\n",regname,x.xfs,val);
                                                        x.xfs=val;
                                                    } else

                                                        if (!strcasecmp("gs",regname)) {
                                                            debug("Changing %s from 0x%x to 0x%x...\n",regname,x.xgs,val);
                                                            x.xgs=val;
                                                        } else

                                                            if (!strcasecmp("cs",regname)) {
                                                                debug("Changing %s from 0x%x to 0x%x...\n",regname,x.xcs,val);
                                                                x.xcs=val;
                                                            } else

                                                                if (!strcasecmp("ss",regname)) {
                                                                    debug("Changing %s from 0x%x to 0x%x...\n",regname,x.xss,val);
                                                                    x.xss=val;
                                                                } else {
                                                                    debug("Unknown register '%s'.\n",regname);
                                                                    return;
                                                                }

    ww=send_message(DMSG_SETREGS,&x,0);
    debug("%s",ww);

}

static void do_back(char* param) {
    char* x;
    x=(void*)send_message(DMSG_GETBACK,0,0);
    debug("%s",x);
}

static void do_addr(char* param) {
    int* x;
    int fifi;
    int st;

    if (!param) {
        debug("Parameter required.\n");
        return;
    }

    if (sscanf(param,"%Li",&l1)!=1) {
        x=(void*)send_message(DMSG_GETADDR,param,0);
        if (!*x) debug("Name '%s' not found.\n",param);
        else {
            debug("Name '%s' has address 0x%08x.\n",param,*x);
            fifi=*x;
            x=(void*)send_message(DMSG_DESCADDR,&fifi,0);
            debug("%s",x);
        }
    } else {
        st=l1;
        LC(l1);
        x=(void*)send_message(DMSG_DESCADDR,&st,0);
        debug("%s",x);
    }
}

static void do_fd(char* param) {
    char* x;
    int st;
    if (!param) {
        debug("Parameter required.\n");
        return;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            debug("Numeric parameter required.\n");
            return;
        }
        st=l1;
        LC(l1);

    }
    x=(void*)send_message(DMSG_DESCFD,&st,0);
    debug("%s",x);
}

static void do_break(char* param) {
    char* x;
    int st;
    if (!param) {
        debug("Parameter required.\n");
        return;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            debug("Numeric parameter required.\n");
            return;
        }
        st=l1;
        LC(l1);

    }
    x=(void*)send_message(DMSG_ABREAK,&st,0);
    debug("%s",x);
}

static void do_fprint(char* param) {
    char* x;
    int st;
    if (!param) {
        debug("Parameter required.\n");
        return;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            debug("Numeric parameter required.\n");
            return;
        }
        st=l1;
        LC(l1);

    }
    x=(void*)send_message(DMSG_FPRINT,&st,0);
    debug("%s",x);
}

static void do_sbreak(char* param) {
    char* x;
    int st;

    if (!param) {
        debug("Parameter required.\n");
        return;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {

            for (st=0;st<256;st++)
                if (scnames[st])
                    if (!strcasecmp(scnames[st],param)) break;

            if (st==256) {
                debug("Invalid syscall name.\n");
                return;
            }
        } else {
            LC(l1);
            st=l1;
        }
    }

    x=(void*)send_message(DMSG_SBREAK,&st,0);
    debug("%s",x);
}

static void do_ibreak(char* param) {
    char* x;
    int st;
    if (!param) {
        debug("Parameter required.\n");
        return;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            for (st=0;st<MAXMYSIG;st++)
                if (my_siglist[st])
                    if (!strcasecmp(param,my_siglist[st])) break;
            if (st==MAXMYSIG) {
                debug("Invalid signal name.\n");
                return;
            }
        } else {
            st=l1;
            LC(l1);
        }

    }
    x=(void*)send_message(DMSG_IBREAK,&st,0);
    debug("%s",x);
}

static void do_ret(char* param) {
    char* x;
    int st;

    if (!param) {
        st=1;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            debug("Numeric parameter required.\n");
            return;
        }
        st=l1;
        LC(l1);

    }

    x=(void*)send_message(DMSG_TORET,&st,0);
    debug("%s",x);
}

static void do_step(char* param) {
    char* x;
    int st;

    if (!param) {
        st=1;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            debug("Numeric parameter required.\n");
            return;
        }
        st=l1;
        LC(l1);

    }

    if (st<0) {
        debug("Nonsense parameter.\n");
        return;
    }

    x=(void*)send_message(DMSG_STEP,&st,0);
    debug("%s",x);
}

static void do_dynamic(char* param) {
    char* x;
    x=(void*)send_message(DMSG_DYNAMIC,0,0);
    debug("%s",x);
}

static void do_del(char* param) {
    char* x;
    int st;

    if (!param) {
        st=1;
    } else {
        if (sscanf(param,"%Li",&l1)!=1) {
            debug("Numeric parameter required.\n");
            return;
        }
        st=l1;
        LC(l1);

    }

    x=(void*)send_message(DMSG_DEL,&st,0);
    debug("%s",x);
}

static void do_libc(char* param) {
    char* x;
    x=(void*)send_message(DMSG_TOLIBCALL,0,0);
    debug("%s",x);
}

static void do_sys(char* param) {
    char* x;
    x=(void*)send_message(DMSG_TOSYSCALL,0,0);
    debug("%s",x);
}

static void do_signals(char* param) {
    char* x;
    x=(void*)send_message(DMSG_SIGNALS,0,0);
    debug("%s",x);
}

static void do_call(char* param) {
    char* x;
    x=(void*)send_message(DMSG_TOLOCALCALL,0,0);
    debug("%s",x);
}

static void do_down(char* param) {
    char* x;
    x=(void*)send_message(DMSG_TOLOWERNEST,0,0);
    debug("%s",x);
}

static void do_list(char* param) {
    char* x;
    x=(void*)send_message(DMSG_LISTBREAK,0,0);
    debug("%s",x);
}

static void do_fdmap(char* param) {
    char* x;
    x=(void*)send_message(DMSG_FDMAP,0,0);
    debug("%s",x);
}

static void do_memmap(char* param) {
    char* x;
    x=(void*)send_message(DMSG_GETMAP,0,0);
    debug("%s",x);
}

static void do_fnmap(char* param) {
    char* x;
    x=(void*)send_message(DMSG_FNLIST,0,0);
    debug("%s",x);
}

static void do_run(char* param) {
    char* x;
    x=(void*)send_message(DMSG_RUN,0,0);
    debug("%s",x);
}

static void do_stop(char* param) {
    char* x;
    x=(void*)send_message(DMSG_STOP,0,0);
    debug("%s",x);
}

static void do_halt(char* param) {
    char* x;
    x=(void*)send_message(DMSG_HALT,0,0);
    debug("%s",x);
}

static void do_next(char* param) {
    char* x;
    x=(void*)send_message(DMSG_TONEXT,0,0);
    debug("%s",x);
}

/******************************************************************************/

// Predefined commands.
struct aegir_cmd cmd[MAXCMD+1] = {
    { "disass",  do_disass,      "disass [ x len ]: disassemble current eip [ or memory region ]" },
    { "regs",    do_regs,        "display registers" },
    { "back",    do_back,        "display call backtrace" },
    { "info",    do_addr,        "info x: get info about name or address x" },
    { "fdinfo",  do_fd,          "fdinfo x: display info about file descriptor x" },
    { "break",   do_break,       "break x: set a breakpoint at address x" },
    { "sbreak",  do_sbreak,      "sbreak x: set a breakpoint on syscall x" },
    { "ibreak",  do_ibreak,      "ibreak x: set a breakpoint on signal x" },
    { "rwatch",  do_rwatch,      "rwatch x y: watch memory region for reads" },
    { "wwatch",  do_wwatch,      "wwatch x y: watch memory region for writes" },
    { "step",    do_step,        "step [ x ]: do a single step [ or x steps ]" },
    { "ret",     do_ret,         "ret [ x ]: continue until [ x-th ] ret" },
    { "libc",    do_libc,        "continue to next libcall" },
    { "log",     do_log,         "log [ file ]: start / stop logging Fenris output" },
    { "sys",     do_sys,         "continue to next syscall" },
    { "call",    do_call,        "continue to next local call" },
    { "down",    do_down,        "continue to ret from current function" },
    { "next",    do_next,        "continue to next line from Fenris" },
    { "run",     do_run,         "continue to next breakpoint or watchpoint" },
    { "dynamic", do_dynamic,     "continue to the main code (skip libc prolog)" },
    { "stop",    do_stop,        "stop program as soon as possible" },
    { "halt",    do_halt,        "stop program NOW" },
    { "fprint",  do_fprint,      "fprint x: fingerprint code at address x" },
    { "x",       do_memdump,     "x x y: display memory region as bytes" },
    { "y",       do_strdump,     "y x: display a string under address x" },
    { "setreg",  do_setreg,      "setreg x y: set register x to value y" },
    { "setmem",  do_setmem,      "setmem x y: set byte at address x to value y" },
    { "list",    do_list,        "list watchpoints and breakpoints" },
    { "del",     do_del,         "del x: delete a watchpoint or breakpoint" },
    { "memmap",  do_memmap,      "display process memory map" },
    { "fdmap",   do_fdmap,       "display process file descriptor map" },
    { "fnmap",   do_fnmap,       "list known local functions" },
    { "signals", do_signals,     "display signal actions" },
    { "load",    load_module,    "load x: load custom debugging module x" },
    { "exec",    exec_cmd,       "exec x: execute shell command x" },
    { "help",   display_help,   "display help" },
    { "?",      display_help,   0 },
    { "quit",   handle_quit,    "quit, exit: terminate the session" },
    { "exit",   handle_quit,    0 }
};

/******************************************************************************/

void register_command(char* commd,void* handler,char* help) {
    int q=0;
    if (!commd) fatal("You cannot register command with null name");
    while (cmd[q].cmd) q++;
    if (q>=MAXCMD) fatal("MAXCMD exceeded");
    cmd[q].cmd=strdup(commd);
    cmd[q].handler=handler;
    cmd[q].help=strdup(help);
}

/******************************************************************************/

struct w_scroll_data{
    char ** scrollback; // line buffers
    int * sb_attr;
    int sb_len; // number of line buffers
    int scroll; // number of lines below the bottom of the window
    int was_nl; // if '\n' was stripped from the last line
    int cur_line;       // index of current line buffer
    int cur_x;
    int height; // ...of the window
};

struct w_scroll_data WSfenris, WSaegir;

void init_scrollback(struct w_scroll_data * wsd, int h)
{
    int i;
    wsd->height=h;
    wsd->scroll=0;
    wsd->sb_len=100;
    wsd->scrollback=malloc(wsd->sb_len * sizeof(char**));
    wsd->sb_attr=malloc(wsd->sb_len * sizeof(int));
    wsd->cur_line=wsd->cur_x=0;
    for(i=0;i<wsd->sb_len;i++)wsd->scrollback[i]=malloc(COLS+1);
}

/******************************************************************************/

void init_ncurses()
{
    initscr();
    start_color();

    init_pair(1,COLOR_YELLOW,   0);
    init_pair(2,COLOR_WHITE,    COLOR_RED);
    init_pair(3,COLOR_WHITE,    COLOR_GREEN);
    init_pair(4,COLOR_WHITE,    COLOR_BLUE);
    init_pair(5,COLOR_CYAN,             0);
    init_pair(6,COLOR_MAGENTA,  0);

    raw();
    noecho();
    nonl();

    Wregs       =newwin(2,0,0,0);
    Wdata       =newwin(WD,0,2,0);
    Wcode       =newwin(WC,0,WD+2,0);
    Wfenris     =newwin(WF,0,WD+WC+2,0);
    Waegir      =newwin(WA,0,WC+WD+WF+2,0);
    Winput      =newwin(1,COLS-3,LINES-1,0);
    Wstatus     =newwin(1,3,LINES-1,COLS-3);

    wbkgdset(Wdata, data_color);
    wclear(Wdata);

    idlok(Waegir,1);
    //immedok(Waegir,1);
    scrollok(Waegir,1);
    wmove(Waegir,WA-1,0);
    init_scrollback(&WSaegir, WA);

    wbkgdset(Wfenris, fenris_color);
    wclear(Wfenris);
    idlok(Wfenris,1);
    //immedok(Wfenris,1);
    scrollok(Wfenris,1);
    wmove(Wfenris,WF-1,0);
    init_scrollback(&WSfenris, WF);

    immedok(Wstatus,1);
    waddstr(Wstatus,"[?]");

    keypad(Winput,1);
    //meta(Winput,1);

    refresh_all(0);
}

/******************************************************************************/

void refresh_all(int t)
{
    if(t){
        touchwin(Wregs);
        touchwin(Wdata);
        touchwin(Winput);
        touchwin(Wcode);
        touchwin(Waegir);
        touchwin(Wfenris);
        touchwin(Wstatus);
    }

    wnoutrefresh(Wregs);
    wnoutrefresh(Wdata);
    wnoutrefresh(Winput);
    wnoutrefresh(Wcode);
    wnoutrefresh(Waegir);
    wnoutrefresh(Wfenris);
    wnoutrefresh(Wstatus);
    doupdate();
}

/******************************************************************************/

void waddstr_with_scrollback(WINDOW *w, char * str, struct w_scroll_data *wsd)
{
    int n=strlen(str);
    int attrs; int z;
    wattr_get(w,&attrs,&z,&z);

    if(wsd->scroll){// FIXME - sometimes we don't need to redraw all lines
        int i;
        werase(w);
        wsd->scroll=0;
        for(i=-wsd->height+1;i<=0;i++){
            int j=(wsd->cur_line+i+wsd->sb_len)%wsd->sb_len;
            wattrset(w,wsd->sb_attr[j]);
            waddstr(w,wsd->scrollback[j]);
            if(i)waddch(w,'\n');
        }
    }

    if(wsd->was_nl){
        scroll(w);
        waddch(w,'\r');
        wsd->scrollback[wsd->cur_line][wsd->cur_x]=0;
        wsd->cur_line=(wsd->cur_line+1)%wsd->sb_len;
        wsd->sb_attr[wsd->cur_line]=attrs;
        wsd->cur_x=0;

        wsd->was_nl=0;
    }

    if(str[n-1]=='\n'){
        wsd->was_nl=1;
        n--;
    }

    for(;n>0;str++,n--){
        if(*str=='\n' || wsd->cur_x==COLS){
            wsd->scrollback[wsd->cur_line][wsd->cur_x]=0;
            wsd->cur_line=(wsd->cur_line+1)%wsd->sb_len;
            wsd->sb_attr[wsd->cur_line]=attrs;
            wsd->cur_x=0;
        }

        if(*str!='\n'){
            wsd->scrollback[wsd->cur_line][wsd->cur_x++]=*str;
        }
        waddch(w,*str);
    }
    wrefresh(w);
}

/******************************************************************************/

void my_waddstr(WINDOW * w, char * str)
{
    if(w==Wfenris)waddstr_with_scrollback(w, str, &WSfenris);
    else if(w==Waegir)waddstr_with_scrollback(w, str, &WSaegir);
    else waddstr(w,str);
}

char tmpbuf[1024];
void my_wprintw(WINDOW * w, char * fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    if(w != Wfenris && w !=Waegir){
        vwprintw(w,fmt,ap);
        va_end(ap);
        return;
    }
    vsnprintf(tmpbuf,sizeof(tmpbuf)-1,fmt,ap);
    tmpbuf[sizeof(tmpbuf)-1]=0;
    my_waddstr(w,tmpbuf);
    va_end(ap);
}

/******************************************************************************/

void my_scroll(WINDOW * w, struct w_scroll_data * wsd, int n)
{
    int i;
    //wprintw(Winput,"\rscrolling by %d (%d)",n,wsd->scroll);
    //wrefresh(Winput);
    for(;n<0;n++){
        if(wsd->scroll == wsd->sb_len - wsd->height){
            beep();
            break;
        }
        wmove(w,0,0); winsertln(w);
        wsd->scroll++;
        i=(wsd->cur_line + wsd->sb_len - wsd->scroll - wsd->height + 1)%wsd->sb_len;
        wattrset(w,wsd->sb_attr[i]);
        waddstr(w,wsd->scrollback[i]);
    }

    for(;n>0;n--){
        if(wsd->scroll==0){
            beep();
            break;
        }
        scroll(w);
        wsd->scroll--;
        i=(wsd->cur_line + wsd->sb_len - wsd->scroll)%wsd->sb_len;
        wattrset(w,wsd->sb_attr[i]);
        scrollok(w,0);  // dirty hack
        mvwaddstr(w,wsd->height-1,0,wsd->scrollback[i]);
        scrollok(w,1);
    }
    wattrset(w,0);
    wrefresh(w);
}

/******************************************************************************/

void clean_exit(int n)
{
    RSTree_destroy(Wcode_info.tree);

    wattrset(Waegir, fatal_color);
    debug("** Your session will be now terminated. You can most likely switch **\n"
            "** to another window to examine output from Fenris before exiting. **\n");
    wrefresh(Waegir);

    werase(Winput);
    wattrset(Winput, running_color);
    my_wprintw(Winput,"Press RETURN to exit (you can still scroll windows)...");
    wrefresh(Winput);
    wnoutrefresh(Wfenris);
    doupdate();

    doupdate();
    while(1) {
        switch (wgetch(Winput)) {
            case KEY_PPAGE:
                my_scroll(Waegir, &WSaegir, -1);
                break;

            case KEY_NPAGE:
                my_scroll(Waegir, &WSaegir, 1);
                break;

            case KEY_UP:
                my_scroll(Wfenris, &WSfenris, -1);
                break;

            case KEY_DOWN:
                my_scroll(Wfenris, &WSfenris, 1);
                break;

            case '\033':
                switch (wgetch(Winput)) {
                    case 'n': my_scroll(Waegir, &WSaegir, -1); break;
                    case 'N': my_scroll(Waegir, &WSaegir, -5); break;
                    case 'm': my_scroll(Waegir, &WSaegir, 1); break;
                    case 'M': my_scroll(Waegir, &WSaegir, 5); break;
                    case 'p': my_scroll(Wfenris, &WSfenris, -1); break;
                    case 'P': my_scroll(Wfenris, &WSfenris, -5); break;
                    case 'l': my_scroll(Wfenris, &WSfenris, 1); break;
                    case 'L': my_scroll(Wfenris, &WSfenris, 5); break;
                }
                break;

            case '\r': goto shutdown_it;
        }
        usleep(10000);
    }

shutdown_it:

    { char* x;
        if ((x=getenv(ENVPIPE))) unlink(x);
        if ((x=getenv(ENVSOCK))) unlink(x);
    }
    noraw();
    endwin();
    if (extralog) fclose(extralog);
    exit(n);
}

/******************************************************************************/

// history length
#define N_BUFFERS       32
#define INPUT_BUFLEN    256

struct buff_struct{
    char buf[INPUT_BUFLEN];
    int len;
};

struct{
    int repeat_last;
} getline_optns;

#define CONTROL(key)    (1+key-'A')
#define ALT(key)        (key<<24)

static char * nc_getline(int ch)                // readline replacement
{
    char * tmp;
    static int cursor=0;
    static int new_buf, cur_buf;
    static struct buff_struct buffers[N_BUFFERS];
    static char * last_buf;

#define C_BUF           (buffers[cur_buf])
    switch(ch){
        case KEY_LEFT:
            if(cursor==0){
                beep();return 0;
            }
            cursor--;
            break;

        case KEY_RIGHT:
            if(cursor==C_BUF.len){
                beep();return 0;
            }
            cursor++;
            break;

        case KEY_UP:
            if(!buffers[(cur_buf+N_BUFFERS-1)%N_BUFFERS].len
                    || (new_buf+1)%N_BUFFERS == cur_buf){
                beep();return 0;
            }
            cur_buf=(cur_buf+N_BUFFERS-1)%N_BUFFERS;
            cursor=C_BUF.len;
            wmove(Winput,0,8); wclrtoeol(Winput);
            waddstr(Winput,C_BUF.buf);
            break;

        case KEY_DOWN:
            if(/*!buffers[(cur_buf+1)%N_BUFFERS].len
                 ||*/ new_buf == cur_buf){
                beep();return 0;
            }
            cur_buf=(cur_buf + 1)%N_BUFFERS;
            cursor=C_BUF.len;
            wmove(Winput,0,8); wclrtoeol(Winput);
            waddstr(Winput,C_BUF.buf);
            break;

        case 127:
        case KEY_BACKSPACE:
            if(cursor==0){
                beep();return 0;
            }
            memmove(C_BUF.buf + cursor-1, C_BUF.buf + cursor, C_BUF.len-cursor+1);
            mvwdelch(Winput,0,8+cursor-1);
            cursor--;C_BUF.len--;
            break;

        case KEY_DC:
            if(cursor==C_BUF.len){
                beep();return 0;
            }
            memmove(C_BUF.buf + cursor, C_BUF.buf + cursor+1, C_BUF.len-cursor);
            wdelch(Winput);
            C_BUF.len--;
            break;

        case CONTROL('A'):
        case KEY_HOME:
            cursor=0;
            break;

        case CONTROL('E'):
        case KEY_END:
            cursor=C_BUF.len;
            break;

        case CONTROL('U'):
            wmove(Winput,0,8);
            memmove(C_BUF.buf, C_BUF.buf + cursor, C_BUF.len-cursor);
            C_BUF.len-=cursor;
            for(;cursor>0;cursor--)wdelch(Winput);
            break;

        case CONTROL('W'):
            {
                char *c; int oldcursor=cursor;

                if(cursor==0){
                    beep();return 0;
                }

                for(c=&C_BUF.buf[cursor-1];*c==' ' && cursor>0;c--){
                    mvwdelch(Winput,0,8+cursor-1);cursor--;
                }

                for(;*c!=' ' && cursor>0;c--){
                    mvwdelch(Winput,0,8+cursor-1);cursor--;
                }

                memmove(c, C_BUF.buf + oldcursor-1, C_BUF.len-oldcursor+1);
                C_BUF.len-=(C_BUF.len-oldcursor+1);
            }
            break;

        case '\r':
        case '\n':
            my_wprintw(Wfenris,"");
            my_wprintw(Waegir,"");

            if(C_BUF.buf[0]){
                last_buf=C_BUF.buf;
            }else{
                if(!getline_optns.repeat_last)return 0;

                if(last_buf){
                    werase(Winput);
                    wrefresh(Winput);
                }
                return last_buf;
            }

            werase(Winput);
            wrefresh(Winput);

            if(cur_buf!=new_buf)
                memcpy(&buffers[new_buf],&buffers[cur_buf], sizeof(struct buff_struct));

            new_buf=(new_buf+1)%N_BUFFERS;

            C_BUF.buf[C_BUF.len]=0;
            tmp=C_BUF.buf;
            cur_buf=new_buf;
            cursor=C_BUF.len=0;
            return tmp;
            break;

        default:
            if(ch<32 || ch>128 || C_BUF.len+8==COLS-3
                    || C_BUF.len==INPUT_BUFLEN-1){
                beep(); return 0;
            }
            winsch(Winput,ch);
            if(cursor<C_BUF.len)
                memmove(C_BUF.buf + cursor+1, C_BUF.buf + cursor, C_BUF.len - cursor);

            C_BUF.buf[cursor]=ch;
            cursor++; C_BUF.len++;
    }

    wmove(Winput,0,cursor+8);
    wrefresh(Winput);
    return 0;
}

/******************************************************************************/

int getcpid(int pid)
{
    char buf[256];
    int l;
    int fd;
    char *c;
    DIR * dir;
    struct dirent * de;
    dir=opendir("/proc/");
    if(!dir)return -1;

    while((de=readdir(dir))){
        if(!isdigit(de->d_name[0]))continue;
        sprintf(buf,"/proc/%s/status",de->d_name);
        fd=open(buf,O_RDONLY);
        if(fd<0)continue;
        l=read(fd,buf,sizeof(buf)-2);
        close(fd);
        if(l<=0)continue;

        buf[l]='\n';
        buf[l+1]=0;
        for(c=buf;c[0]!='P' || c[1]!='P';c=strchr(c,'\n')+1)
            if(!*c)break;

        if(*c){
            if(atoi(c+5)==pid) return atoi(de->d_name);
        }
    }
    return -1;
}

/******************************************************************************/

void reset_wdata_addr()
{
    struct user_regs_struct* x;

    x=(void*)send_message(DMSG_GETREGS,0,0);
    wdata_addr=x->esp-WD*16;
    reg_mem_code_update();
}

void reset_wcode_addr()
{
    struct user_regs_struct* x;

    x=(void*)send_message(DMSG_GETREGS,0,0);
    Wcode_addr=x->eip;
    reg_mem_code_update();
}

/******************************************************************************/

/*
 * 0 < WC_LOOK_BEHIND < MAXFENT
 */
#define WC_LOOK_BEHIND 1024
#define WC_MAX_OPSIZE 20

void Wcode_update() {
    unsigned int pc;
    unsigned int par[2];
    char *mem;
    int *ff;
    int bytes;
    int i=0;

    pc=RSNode_get_key(Wcode_info.tree,Wcode_info.top_node);

    par[0]=pc; par[1]=par[0]+WC*WC_MAX_OPSIZE;
    mem=((char*)(ff=send_message(DMSG_GETMEM,(char*)&par,0)))+4;

    werase(Wcode);

    while (*ff>0 && i<WC) {
        if (pc==Wcode_info.cur_addr) wbkgdset(Wcode, code_color);
        bytes=opdis_disass_one( (FILE*)Wcode, mem, pc);

        /* uff...this line took me (pczerkas) about 30min, but wait a moment...
         * where's that ugly-wrapped bottom line of Wcode window ?!
         */
        if (getcurx(Wcode)>0 || getcury(Wcode)>i+1) i++;

        if (pc==Wcode_info.cur_addr) wbkgdset(Wcode, def);
        RSTree_put_val(Wcode_info.tree,pc,bytes);
        pc+=bytes;
        mem+=bytes;
        *ff-=bytes;
        i++;
    }

    wnoutrefresh(Wcode);
}

int Wcode_move_by(int rows) {
    RSNode nd;
    unsigned int pc;
    unsigned int par[2];
    char *mem;
    int *ff;
    int bytes;

    nd=Wcode_info.top_node;
    pc=RSNode_get_key(Wcode_info.tree,nd);

    if (rows<0) {
        unsigned int prev_pc;
        /* backward loop */
        while ( (nd=RSTree_prev(Wcode_info.tree,nd)) && rows<0 ) {
            prev_pc=RSNode_get_key(Wcode_info.tree,nd);
            bytes=RSNode_get_val(Wcode_info.tree,nd);
            if ((prev_pc+bytes)==pc) { /* matched exactly */
                Wcode_info.top_node=nd;
                pc=prev_pc;
                rows++;
            } else { /* try to match */
                prev_pc+=bytes;
                if (prev_pc>pc)
                    continue; /* overlapped insn, continue main loop */
                /* check distance */
                if ( (prev_pc<pc) && (prev_pc+WC_LOOK_BEHIND>pc) ) {
                    par[0]=prev_pc; par[1]=par[0]+(pc-prev_pc)*WC_MAX_OPSIZE;
                    mem=((char*)(ff=send_message(DMSG_GETMEM,(char*)&par,0)))+4;
                    while (*ff>0 && pc>prev_pc) {
                        bytes=opdis_getopsize(mem,prev_pc);
                        RSTree_put_val(Wcode_info.tree,prev_pc,bytes);
                        prev_pc+=bytes;
                        mem+=bytes;
                        *ff-=bytes;
                    }
                    if (prev_pc != pc)
                        break; /* match failed */
                    else {
                        nd=Wcode_info.top_node; /* match success, continue main loop */
                        continue;
                    }
                } else /* prev_pc too distant */
                    break;
            }
        }
    } else if (rows>0) {
        bytes=RSNode_get_val(Wcode_info.tree,nd);
        pc+=bytes;
        par[0]=pc; par[1]=par[0]+rows*WC_MAX_OPSIZE;
        mem=((char*)(ff=send_message(DMSG_GETMEM,(char*)&par,0)))+4;
        /* forward loop */
        while (*ff>0 && rows>0) {
            nd=RSTree_put(Wcode_info.tree,pc);
            bytes=opdis_getopsize(mem,pc);
            RSNode_set_val(Wcode_info.tree,nd,bytes);
            pc+=bytes;
            mem+=bytes;
            *ff-=bytes;
            rows--;
        }
        Wcode_info.top_node=nd;
    }

    Wcode_update();

    return rows;
}

void Wcode_set_addr(unsigned int addr) {
    unsigned int par[2];
    char *mem;
    int* ff;

    par[0]=addr; par[1]=par[0]+WC_MAX_OPSIZE;
    mem=((char*)(ff=send_message(DMSG_GETMEM,(char*)&par,0)))+4;

    if (*ff>0) {
        Wcode_info.top_node=RSTree_put(Wcode_info.tree,addr);
        Wcode_info.cur_addr=addr;
        Wcode_move_by((1-WC)/2); /* move to the middle of Wcode window
                                  * alternative: Wcode_update()
                                  */
    } else {
        if (!stopped && syscnum<0) {
            werase(Wcode);
            wprintw(Wcode,"%08x:\t<inside a blocking syscall %d [%s]>",addr, -syscnum, scnames[-syscnum & 0xff]);
            wnoutrefresh(Wcode);
        }
    }

}

/******************************************************************************/

#define N_FLAGS 8
const struct {
    char c;
    int o;
} flags[N_FLAGS]=
{{'O',11}, {'D',10}, {'I',9}, {'S',7}, {'Z',6}, {'A',4}, {'P',2}, {'C',0}};
//const char flags[]="C_P_A_ZS_IDO____";

char * reg_mem_code_update()
{
    struct user_regs_struct* x;
    int i;
    char * m;

    x=(void*)send_message(DMSG_GETREGS,0,0);
    wmove(Wregs,0,0);
    wattrset(Wregs, regs_color);
    wprintw(Wregs,"eax 0x%08x  ebx 0x%08x  ecx 0x%08x  edx 0x%08x  esi 0x%08x\n",
            x->eax, x->ebx, x->ecx, x->edx, x->esi);
    wprintw(Wregs,"edi 0x%08x  ebp 0x%08x  esp 0x%08x  eip 0x%08x  flags ",
            x->edi, x->ebp, x->esp, x->eip, x->eflags);

    for(i=0;i<N_FLAGS;i++)
        if (x->eflags & (1<<flags[i].o)) {
            wattrset(Wregs,regs_color);
            waddch(Wregs,flags[i].c);
        } else {
            wattrset(Wregs,def);
            waddch(Wregs,tolower(flags[i].c));
        }

    wmove(Wregs,0,6);
    wnoutrefresh(Wregs);

    if (stopped && !please_disass && Wcode_addr)
        x->eip=Wcode_addr;
    else
        Wcode_addr=x->eip;

    Wcode_set_addr(x->eip);

    m=wmemdump(Wdata,wdata_addr,WD*16,0);
    wmove(Wdata,10,0);
    wnoutrefresh(Wdata);
    doupdate();
    return m;
}

/******************************************************************************/

void inline do_prompt(int n)
{
    werase(Winput);

    wattrset(Winput,(n==0)?prompt_color:cblink_color);
    switch(n){
        case 1:
            wprintw(Winput,"Processing, please wait...");
            break;

        case 2:
            wprintw(Winput,"In data window...");
            break;

        case 3:
            wprintw(Winput,"In registers window...");
            break;

        case 4:
            wprintw(Winput,"Stopping, please wait...\r");
            break;

        case 0:
            doingstop=0;
            wprintw(Winput,PROMPT);
    }
    wattrset(Winput,def);
    wrefresh(Winput);
}

/******************************************************************************/

void gui_help()
{
    WINDOW * help=newwin(0,0,0,0);

    wattrset(help,regs_color);
    waddstr(help,"nc-aegir - an interactive debugger GUI for Fenris\n");
    waddstr(help,"-------------------------------------------------\n");
    waddstr(help,"\n");
    wattrset(help,fatal_color);
    waddstr(help,"  Alt-q and Alt-a    - data window: line up / down\n");
    waddstr(help,"  Alt-z and Alt-x    - code window: line up / down\n");
    waddstr(help,"  Alt-p and Alt-l    - Fenris window: line up / down\n");
    waddstr(help,"  Alt-n and Alt-m    - command window: line up / down\n");
    wattrset(help,def);
    waddstr(help,"  (above commands will advance by one page if used with Shift key)\n");
    wattrset(help,fatal_color);
    waddstr(help,"\n");
    waddstr(help,"  Alt-S              - switch between async and sync command mode\n");
    waddstr(help,"  Alt-R              - turn command repeat on RETURN on or off\n");
    waddstr(help,"  Alt-W              - switch between input, data and registers window\n");
    waddstr(help,"  Alt-0              - reset data display to address from %esp\n");
    waddstr(help,"  Alt-=              - reset code display to address from %eip\n");
    waddstr(help,"  Ctrl+C             - stop soon or stop NOW (if used twice)\n");
    waddstr(help,"\n");
    waddstr(help,"  Alt-H              - display this help screen\n");
    waddstr(help,"\n");
    wattrset(help,cyan_color);
    waddstr(help,"For information on using built-in commands, please type 'help' or refer to the\n");
    waddstr(help,"documentation of Aegir debugger. Note that some built-in commands can be used\n");
    waddstr(help,"to modify display - for example, 'x' or 'disas' with one parameter will change\n");
    waddstr(help,"the address displayed in data and code windows, respectively.\n");
    waddstr(help,"\n");
    wattrset(help,running_color);
    waddstr(help,"Press any key to return... ");

    wrefresh(help);
    wgetch(help);
    delwin(help);

    refresh_all(1);
}

/******************************************************************************/

int screen_pid;

void a_handler(int s)
{
    if(screen_pid>=0)kill(screen_pid,15);
    STDERRMSG("Debugger session closed down.\n");
    exit(0);
}

#define MAG     "\033[0;35m"
#define DAR     "\033[1;30m"
#define CYA     "\033[0;36m"
#define NOR     "\033[0;37m"
#define RED     "\033[1;31m"
#define GRE     "\033[1;32m"
#define YEL     "\033[1;33m"
#define BRI     "\033[1;37m"

/******************************************************************************/

void do_splash(char *what) {
    char bigbuf[100000];
    char *cmd="--undefined--",
         *uid=0,*fp=0,*tfro=0,*tto=0,*cseg=0,*lpro=0,*lout=0,*mac=0,*con=0,
         *sym=0,*par=0,*mwri=0,*ind=0,*rval=0,*add=0, *goaway=0;
    struct termios tios;
    ioctl(0,TCGETS,&tios);

    if (what) cmd=what;

    while (1) {
        char buf[1024];
        char* ana;
        printf(CYA "\n\n\n\n\nWelcome to nc-aegir, the GUI debugger for Fenris!\n" YEL
                "-------------------------------------------------\n");
        printf(BRI "Select / modify options passed to Fenris by specifying the letter associated\n"
                "with the option, eventually followed by the new value. Enter '" YEL "r" BRI "' when done.\n\n");
        printf(DAR "[" YEL "A" DAR "]" NOR " Command / parameters : " MAG "%s\n",cmd);
        printf(DAR "[" YEL "B" DAR "]" NOR " Run as UID           : " MAG "%s\n",uid?uid:"<default>");
        printf(DAR "[" YEL "C" DAR "]" NOR " Fingerprints from    : " MAG "%s\n",fp?fp:"<default>");
        printf(DAR "[" YEL "D" DAR "]" NOR " Limited trace from   : " MAG "%s\n",tfro?tfro:"<disabled>");
        printf(DAR "[" YEL "E" DAR "]" NOR " Limited trace to     : " MAG "%s\n",tto?tto:"<disabled>");
        printf(DAR "[" YEL "F" DAR "]" NOR " Code segment         : " MAG "%s\n",cseg?cseg:"<auto>");
        printf(DAR "[" YEL "G" DAR "]" NOR " Libc prolog          : " MAG "%s\n",lpro?"NOT skipped":"skipped");
        printf(DAR "[" YEL "H" DAR "]" NOR " Libc outro           : " MAG "%s\n",lout?"NOT skipped":"skipped");
        printf(DAR "[" YEL "I" DAR "]" NOR " High-level analysis  : " MAG "%s\n",goaway?"disabled":"enabled");
        printf(DAR "[" YEL "J" DAR "]" NOR " Memory access        : " MAG "%s\n",mac?"reported immediately":"delayed reporting");
        printf(DAR "[" YEL "K" DAR "]" NOR " Conditionals         : " MAG "%s\n",con?"NOT reported":"reported");
        printf(DAR "[" YEL "L" DAR "]" NOR " Symbols              : " MAG "%s\n",sym?"NOT used":"used");
        printf(DAR "[" YEL "M" DAR "]" NOR " Parameters           : " MAG "%s\n",par?"NOT described":"described");
        printf(DAR "[" YEL "N" DAR "]" NOR " Memory writes        : " MAG "%s\n",mwri?"NOT reported":"reported");
        printf(DAR "[" YEL "O" DAR "]" NOR " Indentation          : " MAG "%s\n",ind?"disabled":"enabled");
        printf(DAR "[" YEL "P" DAR "]" NOR " Return values        : " MAG "%s\n",rval?"override":"normal mode");
        printf(DAR "[" YEL "Q" DAR "]" NOR " Additional options   : " MAG "%s\n",add?add:"<none>");
        printf(DAR "[" YEL "r" DAR "]" GRE " I am ready to debug\n");
        printf(DAR "[" YEL "!" DAR "]" RED " I want to exit and cancel!\n\n");
        printf(DAR "Your selection: " BRI );
        fflush(0);

        tios.c_lflag=(tios.c_lflag|ICANON)^ICANON;
        ioctl(0,TCSETS,&tios);

        read(0,buf,1);
        buf[1]=0;
        printf("\n");

        tios.c_lflag=(tios.c_lflag|ICANON);
        ioctl(0,TCSETS,&tios);

        if (!strlen(buf)) continue;
        if (buf[strlen(buf)-1]=='\n') buf[strlen(buf)-1]=0;
        if (!strlen(buf)) continue;
        ana=buf;
        if (ana[1]==' ') {ana[1]=ana[0]; ana++;}

        if ( ( !ana[1] &&
                    ((toupper(buf[0])=='A') ||
                     (!cmd && (toupper(buf[0])=='B')) ||
                     (!uid && (toupper(buf[0])=='B')) ||
                     (!fp && (toupper(buf[0])=='C')) ||
                     (!tfro && (toupper(buf[0])=='D')) ||
                     (!tto && (toupper(buf[0])=='E')) ||
                     (!cseg && (toupper(buf[0])=='F')) ||
                     (!add && (toupper(buf[0])=='Q')))) ) {
            printf(DAR "Please provide a parameter: " BRI );
            fgets(&ana[1],1000,stdin);
            if (!strlen(buf)) continue;
            if (buf[strlen(buf)-1]=='\n') buf[strlen(buf)-1]=0;
            if (!strlen(buf)) continue;
        }

        switch (toupper(buf[0])) {
            case '!': FATALEXIT(NOR "user exit"); break;
            case 'A': if (ana[1]) cmd=strdup(&ana[1]); break;
            case 'B': if (ana[1]) uid=strdup(&ana[1]); else uid=0; break;
            case 'C': if (ana[1]) fp=strdup(&ana[1]); else fp=0; break;
            case 'D': if (ana[1]) tfro=strdup(&ana[1]); else tfro=0; break;
            case 'E': if (ana[1]) tto=strdup(&ana[1]); else tto=0; break;
            case 'F': if (ana[1]) cseg=strdup(&ana[1]); else cseg=0; break;
            case 'G': lpro=(void*)!(int)lpro; break;
            case 'H': lout=(void*)!(int)lout; break;
            case 'I': goaway=(void*)!(int)goaway; break;
            case 'J': mac=(void*)!(int)mac; break;
            case 'K': con=(void*)!(int)con; break;
            case 'L': sym=(void*)!(int)sym; break;
            case 'M': par=(void*)!(int)par; break;
            case 'N': mwri=(void*)!(int)mwri; break;
            case 'O': ind=(void*)!(int)ind; break;
            case 'P': rval=(void*)!(int)rval; break;
            case 'Q': if (ana[1]) add=strdup(&ana[1]); else add=0; break;
            case 'R': goto i_am_free;

        }
    }

i_am_free:

    bigbuf[0]=0;

    if (uid) { strcat(bigbuf,"-u '"); strcat(bigbuf,uid); strcat(bigbuf,"' "); }
    if (fp) { strcat(bigbuf,"-L '"); strcat(bigbuf,fp); strcat(bigbuf,"' "); }
    if (tfro || tto) {
        strcat(bigbuf,"-R '");
        if (tfro) strcat(bigbuf,tfro);
        strcat(bigbuf,":");
        if (tto) strcat(bigbuf,tto);
        strcat(bigbuf,"' ");
    }

    if (cseg) { strcat(bigbuf,"-X '"); strcat(bigbuf,cseg); strcat(bigbuf,"' "); }
    if (lpro) strcat(bigbuf,"-s ");
    if (lout) strcat(bigbuf,"-x ");
    if (mac) strcat(bigbuf,"-y ");
    if (con) strcat(bigbuf,"-C ");
    if (sym) strcat(bigbuf,"-S ");
    if (par) strcat(bigbuf,"-d ");
    if (mwri) strcat(bigbuf,"-m ");
    if (ind) strcat(bigbuf,"-i ");
    if (rval) strcat(bigbuf,"-A ");
    if(goaway) strcat(bigbuf,"-G ");
    if (add) { strcat(bigbuf,add); strcat(bigbuf," "); }
    strcat(bigbuf," -- "); strcat(bigbuf,cmd);
    setenv(ENVCMD,bigbuf,1);

}

/******************************************************************************/

char edit_buf[WD*16];

void memwrite(char * buf, unsigned int addr, int len)
{
    unsigned int par[2];
    par[0]=addr;
    for(;len>0;buf++,len--){
        par[1]=*buf;
        send_message(DMSG_SETMEM,(char*)&par,0);
        par[0]++;
    }
}
/******************************************************************************/

int scroll_data(int by, int ed)
{
    static int lock=0;  // negative - disable scrolling up
    // positive - disable scrolling down
    char * mem;

    if(lock==((by>0)?1:-1))return 0;
    if(ed){
        if(by>0){
            memwrite(edit_buf, wdata_addr, ((by>WD)?WD:by)*16);
        }else{
            int b=(-by>WD)?WD:-by;
            memwrite(edit_buf+(WD-b)*16, wdata_addr+(WD-b)*16, b*16);
        }
    }
    wdata_addr+=16*by;
    mem=reg_mem_code_update();
    if(!mem){
        wdata_addr-=16*by;
        reg_mem_code_update();
        lock=(by>0)?1:-1;
        return 0;
    }else lock=0;

    if(ed)memcpy(edit_buf, mem, WD*16);
    return 1;
}

/******************************************************************************/

int edit_data(int ch)
{
    static int cx, cy;
    static int mode;    // 0 - hex, 1 - ascii
    char * mem;

    switch (ch) {
        case 0:
            cx=cy=0;
            mode=0;
            {
                unsigned int par[2]={wdata_addr, wdata_addr+WD*16};
                mem=send_message(DMSG_GETMEM,(char*)&par,0);
            }
            if(!mem)return 0;
            memcpy(edit_buf, mem+4, WD*16);
            break;

        case KEY_UP:    cy--;           break;
        case KEY_DOWN:  cy++;           break;
        case KEY_RIGHT: cx=(cx | 1)+1;  break;
        case KEY_BACKSPACE:
        case KEY_LEFT:  cx=cx+(cx & 1)-2;       break;

        case KEY_NPAGE:
                        if(!scroll_data(WD,1))return 0;
                        break;

        case KEY_PPAGE:
                        /*
                           memwrite(edit_buf, wdata_addr, WD*16);
                           wdata_addr-=WD*16;
                           mem=reg_mem_code_update();
                           if(!mem)return 0;
                           memcpy(edit_buf, mem, WD*16);*/
                        if(!scroll_data(WD,1))return 0;
                        break;

        case 9: // tab
                        if(mode==0){
                            mode=1; cx &= ~1;
                        }else mode=0;
                        break;

                        // Edycja TYLKO w stopped, nawet jesli
                        // jest async.
        case '\r':
        case '\n':
                        // apply changes
                        memwrite(edit_buf, wdata_addr, WD*16);
        case '\033':
                        reg_mem_code_update();
                        return 0;

        default:
                        if(ch>256)break;
                        if(mode==0){
                            int n;
                            if(!isxdigit(ch))break;
                            if(isupper(ch))ch+=32;

                            if(isdigit(ch))n=ch-'0';
                            else n=ch-'a'+10;

                            if(cx & 1){
                                edit_buf[cy*16+cx/2] = ( edit_buf[cy*16+cx/2] & 0xf0 ) | n;
                            }else{
                                edit_buf[cy*16+cx/2] = ( edit_buf[cy*16+cx/2] & 0x0f ) | (n<<4);
                            }
                        }

                        if(mode==1){
                            if(!isprint(ch))break;
                            edit_buf[cy*16+cx/2] = ch;
                        }

                        wmove(Wdata, cy, 10 + 3*(cx/2) + (cx/8));
                        wprintw(Wdata, "%02x", (unsigned char)edit_buf[cy*16+cx/2]);
                        wmove(Wdata, cy, 63 + cx/2);
                        waddch(Wdata,isprint(edit_buf[cy*16+cx/2])?edit_buf[cy*16+cx/2]:'.');

                        if(mode==0) cx++;
                        else cx+=2;

                        if(cx==32){
                            cy++;cx=0;
                            if(cy==WD){
                            }
                        }
                        break;
    }

    if(cx==32){
        cx=0;
        cy++;
    }

    if(cx<0){
        cx=30; cy--;
    }

    if(cy==WD){
        cy--;/*
                memwrite(edit_buf, wdata_addr, 16);
                wdata_addr+=16;
                mem=reg_mem_code_update();
                if(!mem)return 0;
                memcpy(edit_buf, mem, WD*16);*/
        if(!scroll_data(1,1))return 0;
    }

    if(cy<0){
        cy=0;/*
                memwrite(edit_buf+(WD-1)*16, wdata_addr+(WD-1)*16, 16);
                wdata_addr-=16;
                mem=reg_mem_code_update();
                if(!mem)return 0;
                memcpy(edit_buf, mem, WD*16);*/
        if(!scroll_data(-1,1))return 0;
    }

    if(mode==0)
        wmove(Wdata, cy, 10 + 3*(cx/2) + (cx & 1) + (cx/8));
    else
        wmove(Wdata, cy, 63 + cx/2);
    return 1;
}

/******************************************************************************/
/*
 * const char flags[]="C_P_A_ZS_IDO____";
 *        for(i=0;i<N_FLAGS;i++)
 if (x->eflags & (1<<flags[i].o)) {
 wattrset(Wregs,regs_color);
 waddch(Wregs,flags[i].c);
 } else {
 wattrset(Wregs,def);
 waddch(Wregs,tolower(flags[i].c));
 }

 */

int edit_regs(int ch)
{
    static struct user_regs_struct x;
    long * regs[] = { &x.eax, &x.ebx, &x.ecx, &x.edx, &x.esi,
        &x.edi, &x.ebp, &x.esp, &x.eip, 0 };
    static int r,p;

    switch (ch) {
        case 0:
            if(!send_message(DMSG_GETREGS,0,&x))return 0;
            r=0;
            p=7;
            break;

        case KEY_RIGHT:
            if(!p){
                beep();
                break;
            }
            p--;
            break;

        case KEY_LEFT:
            if(p==7){
                beep();
                break;
            }
            p++;
            break;

        case 9: // tab
            p=7; r=(r+1)%10;
            break;

            // Edycja TYLKO w stopped, nawet jesli
            // jest async.
        case '\r':
        case '\n':
            send_message(DMSG_SETREGS,&x,0);
        case '\033':
            return 0;
            break;

        case ' ':
            if(regs[r]) break;
            // only for eflags
            x.eflags ^= (1 << flags[7-p].o);
            if(x.eflags & (1 << flags[7-p].o)){
                wattrset(Wregs,regs_color);
                waddch(Wregs,flags[7-p].c);
            } else {
                wattrset(Wregs,def);
                waddch(Wregs,tolower(flags[7-p].c));
            }
            break;

        default:
            if(ch>256)return 1;
            if(regs[r]){        // not eflags
                if(isxdigit(ch)){
                    int n;
                    unsigned int * tmp=(unsigned int *)(regs[r]);
                    if(isupper(ch))ch+=32;

                    if(isdigit(ch))n=ch-'0';
                    else n=ch-'a'+10;

                    *tmp=( *tmp & ~(7<<(p*4)) ) | (n<<(p*4));
                    wattrset(Wregs, regs_color);
                    waddch(Wregs, ch);

                    if(p)p--;
                }
            }
    }

    wmove(Wregs, (r/5), 6 + (r%5)*16 + (7-p));
    return 1;
}
#undef uregs

/******************************************************************************/

static void usage(char *name) {
    STDERRMSG("Usage: %s [ -i ] program_name [ parameters ]\n\n",name);
    STDERRMSG("  -i            - use Intel notation for disassembly.\n\n");
    exit(1);
}

int doplease;

int main(int argc,char* argv[])
{
    char opt;
    char T_intel=0;
    char * input_buffer;
    int fpfd=0;
    int async=0;
    int mychild;
    char *envpipe, *envsock, *envcmd;
    int active_window=0;        // 0 - Winput, 1 - Wdata, 2 - Wregs
    char* win_wrapper;
    char winchange=0;
    opdis_options opdis_options;

    while ((opt=getopt(argc, argv, "+i")) != -1)
        switch (opt) {
            case 'i':
                T_intel=1;
                break;
            default:
                usage(argv[0]);
        }

    if(!(envpipe=getenv(ENVPIPE)) || !(envsock=getenv(ENVSOCK)) || !(envcmd=getenv(ENVCMD))) {
        char fname[1024];
        char fenhome[1024];
        char cmdbuf[100000];
        char* HOME;

        // Do a splash screen.
        // setenv ENVCMD
        setenv(ENVCMD,"ls",1);

        { int i;
            cmdbuf[0]=0;
            for (i=optind;i<argc;i++) {
                strcat(cmdbuf,argv[i]);
                strcat(cmdbuf," ");
            }
        }

        do_splash(argc>optind?cmdbuf:0);

        HOME=getenv("HOME");
        if (!HOME) HOME=".";
        sprintf(fenhome,"%s/.fenris",HOME);
        mkdir(fenhome,0700);

        sprintf(fname,"%s/.fpipe-%d-%u",fenhome,getpid(),(int)time(0));
        mkfifo(fname,0700);
        setenv(ENVPIPE,fname,1);

        sprintf(fname,"%s/.fsock-%d-%u",fenhome,getpid(),(int)time(0));
        unlink(fname);
        setenv(ENVSOCK,fname,1);
        if (!getenv("DISPLAY")) {
            if (getenv("STY")){
                STDERRMSG(BRI
                        "\nWARNING: You are trying to run nc-aegir from inside an existing\n"
                        "'screen' session. This program requires a separate, dedicated session,\n"
                        "and such a session will be spawned. You'd have to press your meta key\n"
                        "twice to switch between screens." NOR "\n\n");
                sleep(5);
            }

            if(!(screen_pid=fork())) {
                char *args[5]={"screen","-m",argv[0],&cmdbuf[0],0};
                cmdbuf[0]=0;
                if (optind>1)
                    strcat(cmdbuf,argv[1]);
                execvp("screen", args);
                perror("execve('screen')");
                exit(1);
                exit(0);
            }
            usleep(100000);
            screen_pid=getcpid(screen_pid);

            signal(SIGHUP, a_handler);
            signal(SIGCHLD, a_handler);
            pause();
            STDERRMSG("Debugger session closed down.\n");
            exit(0);
        } else {
            // g³upie to trochê, ale "prowizorka rzecz najtrwalsza"
            envpipe=getenv(ENVPIPE);
            envsock=getenv(ENVSOCK);
            envcmd=getenv(ENVCMD);
        }
    }

    signal(SIGCLD,SIG_IGN);
    //system("screen -X zombie xy");

    if (!getenv("DISPLAY")) win_wrapper="screen"; else win_wrapper="xterm -e";

    if(!(mychild=fork())) {
        char buf[200000];
        if (!access("./fenris",X_OK)) {
            sprintf(buf,"%s ./fenris -q -W '%s' -o '#%s' %s", win_wrapper,
                    envsock, envpipe, envcmd);
        } else {
            sprintf(buf,"%s fenris -q -W '%s' -o '#%s' %s", win_wrapper,
                    envsock, envpipe, envcmd);
        }
        execl("/bin/sh","sh","-c",buf,0);
        perror("execve('/bin/sh')");
        exit(1);
    }

    fpfd=open(envpipe, O_RDONLY | O_NONBLOCK);
    if (fpfd < 0) {
        perror("open on ENVPIPE");
        exit(1);
    }
    fcntl(fpfd,F_SETFL,0);

    { int cnt;
        for (cnt=0;cnt<50;cnt++) {
            if(!access(envsock, F_OK)) break;
            usleep(50000);
        }
        if (cnt==50) FATALEXIT("couldn't contact Fenris");
    }

    // switch back to aegir window
    if (!getenv("DISPLAY"))
        system("screen -X select 0 &>/dev/null");

    async=0;

    init_ncurses();

    Wcode_info.tree=RSTree_create();

    opdis_options.print_func=(opdis_print_func)nc_fprintf;
    opdis_options.notation=T_intel>0 ? DIS_NOTN_INTEL : DIS_NOTN_ATT;
    opdis_init(&opdis_options);

    connect_to_fenris(envsock);
    reset_wdata_addr();

    wattrset(Waegir,cyan_color);
    debug(
            ".---------------------------------------------------------------------.\n"
            "| -= Welcome to nc-aegir - an interactive debugger GUI for Fenris! =- |\n"
            "|---------------------------------------------------------------------|\n"
            "|    - brought to you by Andrzej Szombierski and Michal Zalewski -    |\n"
            "| Press 'Alt-H' for GUI help, or type 'help' for debugger shell help. |\n"
            "`---------------------------------------------------------------------'\n\n");
    wattrset(Waegir,def);

    getline_optns.repeat_last=1;
    if(async) do_prompt(0);

    while (1) {
        struct timeval tv;
        fd_set f;
        fd_set ex;
        int ch;
        int z;

        // move the cursor to the active window
        switch(active_window){
            case 0:
                if (winchange){
                    if(!sync || stopped)
                        do_prompt(0);
                    else
                        do_prompt(1);
                }
                winchange=0;
                wrefresh(Winput);
                break;

            case 1:
                if (winchange){
                    edit_data(0);
                    do_prompt(2);
                }
                winchange=0;
                wrefresh(Wdata);
                break;

            case 2:
                if (winchange){
                    edit_regs(0);
                    do_prompt(3);
                }
                winchange=0;
                wrefresh(Wregs);
                break;
        }

        if(please_disass){
            if(!async)do_prompt(0);

            reg_mem_code_update();
            please_disass=0;
        }

        if (!async && !stopped) {
            if (doplease) {
                do_prompt(1);
                doplease=0;
            }
        } else doplease=1;

        FD_ZERO(&f);
        FD_SET(0,&f);
        FD_SET(sd,&f);

        FD_ZERO(&ex);
        FD_SET(sd,&ex);

        if(fpfd)FD_SET(fpfd,&f);

        {
            int s;
            tv.tv_sec=0; tv.tv_usec=100000;
            s=select(sd+1,&f,0,&ex,&tv);
            if(!s && !stopped){
                reset_wdata_addr();
                reg_mem_code_update();
            }
        }

        if(FD_ISSET(sd,&ex) || FD_ISSET(sd,&f)) send_message(DMSG_NOMESSAGE,0,0);

        if(fpfd)if(FD_ISSET(fpfd,&f)){
            char buf[1024];
            int n;
            n=read(fpfd,buf,sizeof(buf)-1);
            if (n<0) pfatal("read on ENVPIPE (fenris died?)");

            if(n){
                buf[n]=0;
                my_waddstr(Wfenris,buf);
                do_logappend(buf);
            }
        }

        if(!FD_ISSET(0,&f))continue;

        input_buffer=0;
        ch=wgetch(Winput);

        if(ch=='\033'){ // ehh escape sequences
            nodelay(Winput,1);
            fcntl(0,F_SETFL,O_NONBLOCK);
            ch=wgetch(Winput);
            nodelay(Winput,0);
            fcntl(0,F_SETFL,0);
            if(ch==ERR || ch=='\033')ch='\033';
            else ch=ALT(ch);
        }

        z=0;
        switch(ch){
            case CONTROL('L'): refresh_all(1); break;
            case ALT('n'): my_scroll(Waegir, &WSaegir, -1); break;
            case ALT('N'): my_scroll(Waegir, &WSaegir, -5); break;
            case ALT('m'): my_scroll(Waegir, &WSaegir, 1); break;
            case ALT('M'): my_scroll(Waegir, &WSaegir, 5); break;

            case ALT('p'): my_scroll(Wfenris, &WSfenris, -1); break;
            case ALT('P'): my_scroll(Wfenris, &WSfenris, -5); break;
            case ALT('l'): my_scroll(Wfenris, &WSfenris, 1); break;
            case ALT('L'): my_scroll(Wfenris, &WSfenris, 5); break;

                           // code scrolling
            case ALT('z'): if (Wcode_move_by(-1) != 0) beep(); break;
            case ALT('Z'): if (Wcode_move_by(-5) != 0) beep(); break;
            case ALT('x'): if (Wcode_move_by(1) != 0) beep(); break;
            case ALT('X'): if (Wcode_move_by(5) != 0) beep(); break;

                               // data scrolling
            case ALT('q'): scroll_data(-1,1); break;
            case ALT('Q'): scroll_data(-WD,1); break;
            case ALT('a'): scroll_data(1,1); break;
            case ALT('A'): scroll_data(WD,1); break;

            case ALT('h'):
            case ALT('H'):
                           gui_help();
                           break;

            case ALT('w'):
            case ALT('W'):
                           if(stopped){
                               switch(active_window){
                                   case 1: edit_data(033); break;
                                   case 2: edit_regs(033); break;
                               }
                               active_window=(active_window+1)%3;
                               winchange=1;
                           }
                           break;

            default:
                           z=1;
        }

        if(!z)continue;

        switch(active_window){
            case 0:
                switch(ch){
                    case ALT('0'):
                        reset_wdata_addr();
                        break;

                    case ALT('='):
                        reset_wcode_addr();
                        break;

                    case KEY_PPAGE:
                        my_scroll(Waegir, &WSaegir, -1);
                        break;

                    case KEY_NPAGE:
                        my_scroll(Waegir, &WSaegir, 1);
                        break;

                    case CONTROL('C'):
                        if(!async && !stopped){
                            if (doingstop)do_halt(0);
                            else {
                                do_prompt(4);
                                do_stop(0);
                                doingstop=1;
                            }
                        }else{
                            debug("Use 'quit yes' (or 'q y') to quit.\n");
                        }
                        break;

                    case ALT('s'):
                    case ALT('S'):
                        async^=1;
                        debug("Switched to %ssynchronous input mode.\n",async?"a":"");
                        if(!stopped) do_prompt(0);
                        break;

                    case ALT('r'):
                    case ALT('R'):
                        getline_optns.repeat_last^=1;
                        break;

                    default:
                        if(stopped || async)input_buffer=nc_getline(ch);
                }
                break;

            case 1:
                if(!edit_data(ch)){
                    active_window=0;
                    reg_mem_code_update();
                    do_prompt(0);
                }
                break;

            case 2:
                if(!edit_regs(ch)){
                    active_window=0;
                    reg_mem_code_update();
                    do_prompt(0);
                }
        }

        if(input_buffer){
            struct aegir_cmd * the_one_match=0;
            char matches[1024];
            int nmatches=0;
            int i;
            char *cmdp, *argp;
            int cmdlen;

            for(cmdp=input_buffer;*cmdp==' ';cmdp++);
            for(argp=cmdp;*argp && *argp!=' ';argp++);

            cmdlen=argp-cmdp;

            if (!cmdlen){
                do_prompt(0);
                continue;
            }

            if(*argp) argp++;
            else argp=0;
            matches[0]=0;

            wattrset(Waegir,regs_color);
            debug(">> %s\n",cmdp);
            wattrset(Waegir,def);

            for(i=0;cmd[i].cmd && i<MAXCMD;i++){
                if(!strncasecmp(cmdp, cmd[i].cmd, cmdlen)){
                    the_one_match=&cmd[i];
                    if(nmatches++)strcat(matches, ", ");
                    strcat(matches, cmd[i].cmd);
                }
            }

            if (nmatches>1){
                debug("Ambiguous command. Matches: %s\n",matches);
                do_prompt(0);
                continue;
            }

            if(nmatches==1){
                if(the_one_match->handler){
                    the_one_match->handler(argp);
                    if(async || stopped)do_prompt(0);
                    continue;
                }
                debug("This command is not yet implemented.\n");
            }else{
                debug("Command '%s' unrecognized. Try 'help' for help.\n", cmdp);
            }

            do_prompt(0);
        }
    }
}
