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

    Here are breakpoint handling routines and communication code needed
    to talk with Aegir or any other debugger. This file exists so that
    modification to Fenris can be minimized.

 */

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/fcntl.h>
#include <time.h>
#include <alloca.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <bfd.h>

#include "fenris.h"
#include "fdebug.h"
#include "hooks.h"
#include "libfnprints.h"

#include "common.h"

//FIXME: odd, ostream NEVER created, only extern'd
#undef debug
#define debug(x...) fprintf(ostream,x)

//FIXME: only extern'd here, also, fatal never created that I can find. We'll see
extern FILE* ostream;
extern void fatal(const char* x, const int err);

extern struct signed_user_regs_struct r;        // Current process: registers
extern struct fenris_process*  current;  // Currently traced process
extern int T_dostep;
extern char T_goaway;

int was_blocking;

//FIXME: hardcoded?!?  more than 300+ for i386
extern char* scnames[256];

int break_stopped;      // Is the code stopped?
int sd;                 // Our socket to the shell
int curmode;            // Current mode (see MODE_* in hooks.h)
int modepar;            // Current mode parameter, if any.
int break_continuing;   // Recovering from stopped inside singlestep()?
extern char is_static;

#define BP_SYS          1
#define BP_SIG          2
#define BP_ADDR         3
#define BP_R            4
#define BP_W            5

struct break_bpnt {
    char type;  // BP_*
    unsigned int param;
    unsigned int param2;
};

struct break_bpnt bp[MAXBREAK];

char* break_getname(unsigned int addr);

char break_shutup;
int  blocking_syscall;

void send_message(int type,void* data,int len) {
    int q;
    struct dmsg_header d;

    if (sd<=0) return;

    d.magic1=DMSG_MAGIC1;
    d.magic2=DMSG_MAGIC2;

    if ((type!=DMSG_REPLY) && (type!=DMSG_ASYNC))
        fatal("unknown message type in send_message",0);

    d.type=type;
    if (!blocking_syscall) d.code_running=!break_stopped;
    else d.code_running=-(blocking_syscall);

    errno=0;
    q=write(sd,&d,sizeof(struct dmsg_header));
    if (q!=sizeof(struct dmsg_header)) {
        if (break_shutup) return;
        fatal("cannot send message to debugger",errno);
    }

    if (data && len) {
        q=write(sd,data,len);
        if (q!=len) fatal("short write to debugger",errno);
    }

};

char str_buf[MAXFENT];

char* get_string_sock(int sock) {
    char t[2];
    t[1]=0;
    str_buf[0]=0;
    fcntl(sock,F_SETFL,O_SYNC);
    while (1) {
        if (read(sock,t,1)!=1)
            fatal("short read in get_string_sock from client",0);
        if (!t[0]) {
            fcntl(sock,F_SETFL,O_NONBLOCK);
            return str_buf;
        }
        strcat(str_buf,t);
        if (strlen(str_buf)>=sizeof(str_buf)-2)
            fatal("string from client is of excessive length",0);
    }
    fatal("Another broken Turing machine. Rhubarb.",0);
}

#define send_asynctext(x) send_message(DMSG_ASYNC,(x),strlen(x)+1)
#define send_synctext(x) send_message(DMSG_REPLY,(x),strlen(x)+1)

void del_break(int i) {
    char buf[1000];

    if (i<0 || i>=MAXBREAK) {
        send_synctext("Breakpoint number of out range.\n");
        return;
    }

    switch (bp[i].type) {
        case 0:       send_synctext("There is no such breakpoint active.\n");
                      break;

                      //FIXME: hardcoded?!?  more than 300+ for i386
        case BP_SYS:  sprintf(buf,"Deleted on-syscall breakpoint previously set to '%s'.\n",scnames[bp[i].param & 0xff]);
                      send_synctext(buf);
                      break;

        case BP_SIG:  sprintf(buf,"Deleted on-signal breakpoint previously set to signal %d.\n",bp[i].param);
                      send_synctext(buf);
                      break;

        case BP_ADDR: sprintf(buf,"Deleted breakpoint at 0x%x.\n",bp[i].param);
                      send_synctext(buf);
                      break;

        case BP_R:    sprintf(buf,"Deleted read watchpoint at 0x%x-0x%x.\n",bp[i].param,bp[i].param2);
                      send_synctext(buf);
                      break;

        case BP_W:    sprintf(buf,"Deleted write watchpoint at 0x%x-0x%x.\n",bp[i].param,bp[i].param2);
                      send_synctext(buf);
                      break;

        default:      send_synctext("Fascinating programming glitch.\n");

    }

    bp[i].type=0;

}

void add_break(int type,int p1,int p2) {
    int i;
    char buf[1000];

    for (i=0;i<MAXBREAK;i++) if (!bp[i].type) break;

    if (i==MAXBREAK) {
        send_synctext("No free breakpoint slots (delete some old first).\n");
        return;
    }

    bp[i].type=type; bp[i].param=p1; bp[i].param2=p2;

    sprintf(buf,"Breakpoint #%d added.\n",i);
    send_synctext(buf);

}

void list_break(void) {
    int i,tot=0;
    char buf[1000];
    char obuf[sizeof(buf)*MAXBREAK];

    obuf[0]=0;

    for (i=0;i<MAXBREAK;i++) {
        if (!bp[i].type) continue;
        tot++;
        switch (bp[i].type) {
            //FIXME: hardcoded?!?  more than 300+ for i386
            case BP_SYS:  sprintf(buf,"%02d: stop on syscall %s (%d)\n",i,scnames[bp[i].param & 0xff],bp[i].param);
                          strcat(obuf,buf);
                          break;

            case BP_SIG:  sprintf(buf,"%02d: stop on signal %d\n",i,bp[i].param);
                          strcat(obuf,buf);
                          break;

            case BP_ADDR: sprintf(buf,"%02d: stop at address 0x%x.\n",i,bp[i].param);
                          strcat(obuf,buf);
                          break;

            case BP_R:    sprintf(buf,"%02d: stop on read 0x%x-0x%x.\n",i,bp[i].param,bp[i].param2);
                          strcat(obuf,buf);
                          break;

            case BP_W:    sprintf(buf,"%02d: stop on write 0x%x-0x%x.\n",i,bp[i].param,bp[i].param2);
                          strcat(obuf,buf);
                          break;

            default:      sprintf(buf,"%02d: amazingly unknown breakpoint.\n",i);
                          strcat(obuf,buf);

        }
    }

    if (!tot) sprintf(obuf,"No active breakpoints.\n");
    send_synctext(obuf);

}

void break_listen(char* where,const char** argv) {
    struct sockaddr_un sun;

    unlink(where);

    if ((sd = socket (AF_LOCAL, SOCK_STREAM, 0))<0)
        fatal("cannot create a socket",errno);

    sun.sun_family = AF_LOCAL;
    strncpy (sun.sun_path, where, UNIX_PATH_MAX);

    if (bind (sd, (struct sockaddr*)&sun,sizeof (sun)))
        fatal("cannot bind",errno);

    if (listen(sd,1))
        fatal("cannot listen",errno);

    debug("# Ready to accept debug session at %s.\n",where);

    if ((sd=accept(sd,0,0))<0)
        fatal("accept failed",errno);

    debug("# Connection accepted! Entering interactive session.\n");

    { char buf[MAXFENT];
        int n=1;
        char* data;
        int q=time(0);
        data=(void*)ctime((void*)&q);
        if (data[strlen(data)-1]=='\n') data[strlen(data)-1]=0;

        sprintf(buf,"Welcome to Fenris debugger %s build %s running at PID %d.\n"
                "Copyright (C) 2001, 2002 by Michal Zalewski <lcamtuf@coredump.cx>\n\n"
                "Cur. time : %s\n"
                "Executable: %s\n"
                "Arguments : ", VERSION, BUILD, getpid(),data, argv[1]);

        if (!argv[n+1]) strcat(buf,"<NULL>"); else
            while (argv[++n]) {
                strcat(buf,argv[n]);
                strcat(buf," ");
            }

        strcat(buf,"\n\n");

        send_asynctext(buf);

    }

}

extern int pid;
extern unsigned int get_handler(int i);

void get_mem(unsigned int start, unsigned int end) {
    unsigned int re=0,i=0;
    unsigned int totlen=end-start;
    int *first;
    int *buf;
    char* cbuf;

    if (end <= start) fatal("malformed GETMEM request",0);

    if (totlen > MAXFENT-8) totlen=MAXFENT-8;

    first=buf=alloca(totlen+16);
    if (!first) fatal("alloca failed",0);
    buf++;
    cbuf=(char*)buf;

    while (re<totlen) {
        errno=0;
        *buf=ptrace(PTRACE_PEEKDATA,pid,start+re,0);
        if (errno) break;
        buf++;
        re+=4;
    }

    // Restore RET or NOP as needed.
    for (i=0;i<MAXSIG;i++) {
        unsigned int h=get_handler(i);
        if (h) {
            h--;
        }
        if ((h >= start) && (h <= end)) {
            if (current->shret[i]) {
                cbuf[h-start]=0xc3;
            } else {
                cbuf[h-start]=0x90;
            }
        }
    }

    *first=re>totlen?totlen:re;

    send_message(DMSG_REPLY,first,*first+4);
}

void get_regs(void) {
    struct signed_user_regs_struct x;
    if (ptrace(PTRACE_GETREGS,pid,0,&x)) memcpy(&x,&r,sizeof(x));
    send_message(DMSG_REPLY,&x,sizeof(x));
}

void set_regs(void) {
    struct signed_user_regs_struct x;
    if (read(sd,&x,sizeof(x))!=sizeof(x)) fatal("short read from client",0);
    ptrace(PTRACE_SETREGS,pid,0,&x);
    ptrace(PTRACE_GETREGS,pid,0,&r);

    //FIXME: 64bit
    /*
     * if (x.eax != r.eax) send_synctext("Failed to modify eax (blame ptrace).\n"); else
     *     if (x.ebx != r.ebx) send_synctext("Failed to modify ebx (blame ptrace).\n"); else
     *         if (x.ecx != r.ecx) send_synctext("Failed to modify ecx (blame ptrace).\n"); else
     *             if (x.edx != r.edx) send_synctext("Failed to modify edx (blame ptrace).\n"); else
     *                 if (x.esp != r.esp) send_synctext("Failed to modify esp (blame ptrace).\n"); else
     *                     if (x.eip != r.eip) send_synctext("Failed to modify eip (blame ptrace).\n"); else
     *                         if (x.ebp != r.ebp) send_synctext("Failed to modify ebp (blame ptrace).\n"); else
     *                             if (x.esi != r.esi) send_synctext("Failed to modify esi (blame ptrace).\n"); else
     *                                 if (x.edi != r.edi) send_synctext("Failed to modify edi (blame ptrace).\n"); else
     *                                     if (x.eflags != r.eflags) send_synctext("Failed to modify eflags (blame ptrace).\n"); else
     *                                         if (x.xds != r.xds) send_synctext("Failed to modify ds (blame ptrace).\n"); else
     *                                             if (x.xss != r.xss) send_synctext("Failed to modify ss (blame ptrace).\n"); else
     *                                                 if (x.xgs != r.xgs) send_synctext("Failed to modify ss (blame ptrace).\n"); else
     *                                                     if (x.xfs != r.xfs) send_synctext("Failed to modify fs (blame ptrace).\n"); else
     *                                                         if (x.xes != r.xes) send_synctext("Failed to modify es (blame ptrace).\n"); else
     *                                                             if (x.xcs != r.xcs) send_synctext("Failed to modify cs (blame ptrace).\n"); else
     */
                                                                    send_synctext("Register modified successfully.\n");
}

char getnamebuf[1024];

// From Fenris.
extern char* find_id_off(unsigned int c);
extern char* find_name_ex(unsigned int c,char prec,char non);
extern char* lookup_fnct(unsigned int c, unsigned int add,char prec);

const char* my_siglist[] = { "none", "sighup", "sigint", "sigquit",
    "sigill", "sigtrap", "sigabrt", "sigbus", "sigfpe", "sigkill", "sigusr1",
    "sigsegv", "sigusr2", "sigpipe", "sigalrm", "sigterm", "sigchld", "sigcont",
    "sigstop", "sigtstp", "sigttin", "sigttou", "sigurg", "sigxcpu", "sigxfsz",
    "sigvtalrm", "sigprof", "sigwinch", "sigio", "sigpwr", "sigsys", 0 };

char* break_getname(unsigned int addr) {
    char* x;
    getnamebuf[0]=0;
    // First, try library name.
    x=find_name_ex(addr,0,1);
    // Then, try local symbol.
    if (!x) x=lookup_fnct(addr,123456,0);
    // Then, try our own function.
    if (!x) x=find_id_off(addr);
    if (x) strcpy(getnamebuf,x);
    return getnamebuf;
}

extern int CODESEG;

extern int lookup_fnname(char* name);
extern char* get_addrdescr(const unsigned int q);
extern inline char* get_fddescr(const int fd);
extern char already_main;

void break_messenger(void) {
    int q;
    char buf[1000];
    int p[2];
    char* fif;

    struct dmsg_header d;

    if (break_stopped)
        if (!blocking_syscall && was_blocking)
            send_asynctext(">> Successfully stopped after a while.\n");

    was_blocking=blocking_syscall;

loopover:

    // Check for messages.
    fcntl(sd,F_SETFL,O_NONBLOCK);

    errno=0;

    if (break_stopped && (!current || !current->syscall)) {
        fd_set f;
        FD_ZERO(&f);
        FD_SET(sd,&f);
        select(sd+1,&f,0,&f,0);
    }

    q=read(sd,&d,sizeof(struct dmsg_header));

    if (q<=0) {
        if (errno!=EAGAIN) fatal("connection dropped by remote client",-1);
        else { fcntl(sd,F_SETFL,O_SYNC); return; }
    }

    fcntl(sd,F_SETFL,O_SYNC);

    if (d.magic1 != DMSG_MAGIC1) fatal("magic1 incorrect in packet from client",0);
    if (d.magic2 != DMSG_MAGIC2) fatal("magic2 incorrect in packet from client",0);

    switch (d.type) {

        case DMSG_FOO: send_message(DMSG_REPLY,0,0); break;

        case DMSG_SBREAK:
                       if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                       if (T_goaway) { break_goaway(); break; }
                       add_break(BP_SYS,p[0],0);
                       break;

        case DMSG_DEL:
                       if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                       del_break(p[0]);
                       break;

        case DMSG_ABREAK:
                       if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                       add_break(BP_ADDR,p[0],0);
                       break;

        case DMSG_IBREAK:
                       if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                       add_break(BP_SIG,p[0],0);
                       break;

        case DMSG_RWATCH:
                       if (read(sd,&p[0],8)!=8) fatal("short read from client",0);
                       if (T_goaway) { break_goaway(); break; }
                       add_break(BP_R,p[0],p[1]);
                       break;

        case DMSG_WWATCH:
                       if (read(sd,&p[0],8)!=8) fatal("short read from client",0);
                       if (T_goaway) { break_goaway(); break; }
                       add_break(BP_W,p[0],p[1]);
                       break;

        case DMSG_LISTBREAK: list_break(); break;

        case DMSG_GETMEM:
                             if (read(sd,&p[0],8)!=8) fatal("short read from client",0);
                             get_mem(p[0],p[1]);
                             break;

        case DMSG_GETREGS:
                             get_regs();
                             break;

        case DMSG_SETREGS:
                             set_regs();
                             break;

        case DMSG_STEP:
                             errno=0;
                             if (read(sd,&modepar,4)!=4) fatal("short read from client",0);
                             break_stopped=0;
                             curmode=MODE_SINGLE;
                             //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, advancing by %d local code instruction(s)...\n",r.rip,modepar);
                             //FIXME: 64bit
                             if (INLIBC(r.rip))
                                 strcat(buf,"NOTE: you were in libc. Continuing to to local code. Hold on.\n");
                             send_synctext(buf);
                             break;

        case DMSG_GETNAME:
                             if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                             send_synctext(break_getname(p[0]));
                             break;

        case DMSG_STOP:
                             break_stopped=1;
                             curmode=MODE_NONE;
                             if (blocking_syscall) {
                                 //FIXME: 64bit
                                 sprintf(buf,"Trying to stop at 0x%llx, but in blocking call %d [%s]...\n"
                                         "Send SIGTRAP to pid %d or try 'halt' command to stop immediately.\n",r.rip,blocking_syscall,
                                         //FIXME: hardcoded?!?  more than 300+ for i386
                                         scnames[blocking_syscall & 0xff],pid);
                             } else {
                                 //FIXME: 64bit
                                 sprintf(buf,">> Successfully stopped at 0x%llx...\n",r.rip);
                             }
                             send_synctext(buf);
                             break;

        case DMSG_HALT:
                             break_stopped=1;
                             curmode=MODE_NONE;
                             if (blocking_syscall) {
                                 kill(pid,SIGTRAP);
                                 current->syscalldone=1;
                                 sprintf(buf,">> Forced stop at 0x%llx in blocking call %d [%s].\n",
                                         //FIXME: 64bit
                                         r.rip,blocking_syscall,
                                         //FIXME: hardcoded?!?  more than 300+ for i386
                                         scnames[blocking_syscall & 0xff]);
                                 blocking_syscall=0;
                             } else {
                                //FIXME: 64bit
                                 sprintf(buf,">> Successfully stopped at 0x%llx...\n",r.rip);
                             }
                             send_synctext(buf);
                             break;

        case DMSG_RUN:
                             break_stopped=0;
                             curmode=MODE_RUN;
                            //FIXME: 64bit
                             sprintf(buf,"Resuming at 0x%llx...\n",r.rip);
                             send_synctext(buf);
                             break;

        case DMSG_GETADDR:
                             fif=get_string_sock(sd);
                             p[0]=lookup_fnname(fif);
                             send_message(DMSG_REPLY,&p[0],4);
                             break;

        case DMSG_GETBACK:

                             if (T_goaway) { break_goaway(); break; }

                             { char back[MAXFENT];
                                 char small[1000];
                                 unsigned int i;
                                 if (current->fntop<1)
                                     sprintf(back,"No local function calls recorded (you are in main).\n");
                                 else sprintf(back,"Local function calls history (oldest to most recent calls):\n");

                                 for (i=1;i<=current->fntop;i++) {
                                     sprintf(small,"From %x [%s]: fnct_%d ",
                                             current->fnrip[i],break_getname(current->fnrip[i]),
                                             current->fnid[i]);

                                     sprintf(&small[strlen(small)],"[%s] %x, stack %x -> %x\n",
                                             break_getname((*current->fnaddr)[current->fnid[i]-1]),
                                             (*current->fnaddr)[current->fnid[i]-1],
                                             current->frend[i],current->frstart[i]);
                                     strcat(back,small);
                                 }
                                 send_synctext(back);
                             }
                             break;

        case DMSG_DESCADDR:
                             if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                             fif=get_addrdescr(p[0]);
                             if (!strlen(fif))
                                 sprintf(fif=buf,"No additional information about address %x [%s].\n",
                                         p[0],break_getname(p[0]));
                             send_synctext(fif);
                             break;

        case DMSG_DESCFD:
                             if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                             fif=get_fddescr(p[0]);
                             if (!strlen(fif))
                                 sprintf(fif=buf,"No additional information about fd %d.\n",p[0]);
                             send_synctext(fif);
                             break;

        case DMSG_TORET:
                             if (read(sd,&modepar,4)!=4) fatal("short read from client",0);
                             if (T_goaway) { break_goaway(); break; }
                             break_stopped=0;
                             curmode=MODE_RET;
                            //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, continuing to local RET no. %d...\n",r.rip,modepar);
                            //FIXME: 64bit
                             if (INLIBC(r.rip))
                                 strcat(buf,"NOTE: you were in libc. Continuing to to local code. Hold on.\n");
                             send_synctext(buf);
                             break;

        case DMSG_DYNAMIC:
                             if (T_goaway) { break_goaway(); break; }
                             if (is_static) {
                                 send_synctext("This is a statically linked application.\n");
                                 return;
                             }
                             if (already_main) {
                                 send_synctext("You are already in the main code.\n");
                                 return;
                             }
                             break_stopped=0;
                             curmode=MODE_DYN;
                            //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, continuing to the main code...\n",r.rip);
                             send_synctext(buf);
                             break;

        case DMSG_TOLIBCALL:
                             if (T_goaway) { break_goaway(); break; }
                             break_stopped=0;
                             curmode=MODE_LIBCALL;
                            //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, continuing to next libcall...\n",r.rip);
                            //FIXME: 64bit
                             if (INLIBC(r.rip)) {
                                 strcat(buf,"NOTE: you were in libc. Continuing to to local code. Hold on.\n");
                             }
                             send_synctext(buf);
                             break;

        case DMSG_TOSYSCALL:
                             if (T_goaway) { break_goaway(); break; }
                             break_stopped=0;
                             curmode=MODE_SYSCALL;
                            //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, continuing to next syscall...\n",r.rip);
                             send_synctext(buf);
                             break;

        case DMSG_TOLOCALCALL:
                             if (T_goaway) { break_goaway(); break; }
                             break_stopped=0;
                             curmode=MODE_CALL;
                            //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, continuing to next local call...\n",r.rip);
                            //FIXME: 64bit
                             if (INLIBC(r.rip)) {
                                 strcat(buf,"NOTE: you were in libc. Continuing to to local code. Hold on.\n");
                             }
                             send_synctext(buf);
                             break;

        case DMSG_TOLOWERNEST:
                             if (T_goaway) { break_goaway(); break; }
                             break_stopped=0;
                             curmode=MODE_NEST;
                             modepar=current->nest;
                            //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, continuing to lower nest...\n",r.rip);
                             send_synctext(buf);
                             break;

        case DMSG_TONEXT:
                             if (T_goaway) { break_goaway(); break; }
                             break_stopped=0;
                             curmode=MODE_LINE;
                            //FIXME: 64bit
                             sprintf(buf,"At 0x%llx, continuing to next output line...\n",r.rip);
                             send_synctext(buf);
                             break;

        case DMSG_SIGNALS:
                             if (T_goaway) { break_goaway(); break; }
                             { int i;
                                 char buf[MAXFENT];
                                 char small[1000];
                                 int got=0; buf[0]=0;
                                 for (i=1;i<MAXMYSIG;i++)
                                     if (get_handler(i)) {
                                         got=1;
                                         sprintf(small,"- signal %d (%s) handled by 0x%x [%s]\n",i,my_siglist[i],
                                                 get_handler(i),break_getname(get_handler(i)));
                                         strcat(buf,small);
                                     }
                                 if (got) strcat(buf,"All remaining signals have default OS settings.\n");
                                 else strcpy(buf,"No syscall handlers defined, all signals set to default.\n");
                                 send_synctext(buf);
                             }
                             break;

        case DMSG_SETMEM:
                             { unsigned int x;
                                 if (read(sd,&p[0],8)!=8) fatal("short read from client",0);
                                 errno=0;
                                 x=ptrace(PTRACE_PEEKDATA,pid,p[0],0);
                                 if (errno) {
                                     sprintf(buf,"Cannot access memory at address 0x%x.\n",p[0]);
                                     send_synctext(buf);
                                     return;
                                 }
                                 x = (x & 0xffffff00) + (p[1] & 0xff);
                                 errno=0;
                                 ptrace(PTRACE_POKEDATA,pid,p[0],x);
                                 if (errno) {
                                     sprintf(buf,"Cannot modify memory at address 0x%x.\n",p[0]);
                                     send_synctext(buf);
                                     return;
                                 }
                                 sprintf(buf,"Memory at address 0x%x modified.\n",p[0]);
                                 send_synctext(buf);
                             }
                             break;

        case DMSG_KILL:
                             fatal("DMSG_KILL received from client",-1);
                             break;

        case DMSG_FPRINT:
                             {
                                 unsigned char sig[SIGNATSIZE+4];
                                 int i;
                                 unsigned int gotsig;
                                 char buf[MAXFENT];

                                 buf[0]=0;

                                 if (read(sd,&p[0],4)!=4) fatal("short read from client",0);
                                 errno=0;

                                 for (i=0;i<SIGNATSIZE/4;i++)
                                     AS_UINT(sig[i*4])=ptrace(PTRACE_PEEKDATA,pid,p[0]+i*4,0);

                                 if (errno) {
                                     sprintf(buf,"Cannot read memory at address 0x%x - 0x%x.\n",p[0],p[0]+SIGNATSIZE);
                                     send_synctext(buf);
                                     return;
                                 }

                                 gotsig=fnprint_compute(sig,CODESEG);

                                 {

#define MAXTORET 50

                                     unsigned short sht = gotsig & 0xffff;
                                     int got=0;
                                     struct fenris_fndb *cur;
                                     cur=fndb[gotsig>>16];
                                     while (cur) {
                                         if (cur->a == sht) {
                                             if (!got) {
                                                 sprintf(buf,"Matches for signature %08X: %s",gotsig,cur->name);
                                             } else {
                                                 if (got==MAXTORET) {
                                                     strcat(buf,", ...");
                                                 } else if (got<MAXTORET) {
                                                     strcat(buf,", ");
                                                     strcat(buf,cur->name);
                                                 }
                                             }
                                             got++;
                                         }
                                         cur=cur->next;
                                     }
                                     if (!got) sprintf(buf,"Signature %08X, no matches.\n",gotsig);
                                     else strcat(buf,"\n");
                                 }

                                 send_synctext(buf);
                             }
                             break;

        case DMSG_GETMAP:
        case DMSG_FDMAP:
        case DMSG_FNLIST:
                             if (T_goaway) { break_goaway(); break; }
                             sprintf(buf,"This functionality is not yet implemented.\n");
                             send_synctext(buf);
                             break;

        default: fatal("unrecognized message from client",0);

    }

    goto loopover;

}

int clearentity;
char break_entity[MAXFENT];
extern char T_nolast;

void break_sendentity(void) {
    if (!T_nolast)
        send_asynctext(break_entity);
    break_entity[0]=0;
    clearentity=0;
}

void break_sendentity_force(void) {
    send_asynctext(break_entity);
    break_entity[0]=0;
    clearentity=0;
}

void break_newline(void) {
    char buf[1000];
    clearentity=1;
    if (curmode == MODE_LINE)
        if (strlen(break_entity)) {
            curmode=MODE_NONE;
            break_stopped=1;
            break_sendentity();
            //FIXME: 64bit
            sprintf(buf,">> New line stop at 0x%llx [%s].\n",r.rip,break_getname(r.rip));
            send_asynctext(buf);
        }
}

void break_append(char* fmt) {
    if (clearentity) { break_entity[0]=0; clearentity=0; }
    if (strlen(break_entity)+strlen(fmt)+1>=sizeof(break_entity))
        fatal("break_append overflow",0);
    strcat(break_entity,fmt);
}

int should_be_stopped(void) { return !curmode; }

int break_single(void) {
    char buf[1000];
    int i;

    for (i=0;i<MAXBREAK;i++)
        if (bp[i].type == BP_ADDR)
            //FIXME: 64bit
            if (bp[i].param == r.rip) {
                curmode=MODE_NONE;
                break_stopped=1;
                break_continuing=1;
                break_sendentity();
                //FIXME: 64bit
                sprintf(buf,">> Breakpoint #%d stop at 0x%llx [%s].\n",i,r.rip,break_getname(r.rip));
                send_asynctext(buf);
                return 0;
            }

    if (curmode==MODE_SINGLE) {
        modepar--;
        if (modepar<=0) {
            curmode=MODE_NONE;
            break_continuing=1;
            break_stopped=1;
            break_sendentity();
            //FIXME: 64bit
            sprintf(buf,">> Singlestep stop at 0x%llx [%s].\n",r.rip,break_getname(r.rip));
            send_asynctext(buf);
            return 0;
        }
    }

    // Avoid needless continuation if stopped.
    if (curmode==MODE_NONE) {
        break_continuing=1;
        return 0;
    }

    return 1;

}

void break_exitcond(void) {
    break_sendentity();
    send_asynctext(">> No more processes to trace. Fenris will now terminate.\n");
}

void break_libcall(unsigned int addr) {
    int i;
    char buf[1000];

    for (i=0;i<MAXBREAK;i++)
        if (bp[i].type == BP_ADDR)
            if (bp[i].param == addr) {
                curmode=MODE_NONE;
                break_continuing=1;
                break_stopped=1;
                break_sendentity();
                //FIXME: 64bit
                sprintf(buf,">> LIBCALL breakpoint #%d (0x%x) stop at 0x%llx [%s].\n",i,addr,r.rip,break_getname(r.rip));
                send_asynctext(buf);
            }

    if (curmode == MODE_LIBCALL) {
        curmode=MODE_NONE;
        break_continuing=1;
        break_stopped=1;
        break_sendentity();
        //FIXME: 64bit
        sprintf(buf,">> Libcall 0x%x reached at 0x%llx [%s].\n",addr,r.rip,break_getname(r.rip));
        send_asynctext(buf);
    }

}

void break_syscall(unsigned int num) {
    int i;
    char buf[1000];

    for (i=0;i<MAXBREAK;i++)
        if (bp[i].type == BP_SYS)
            if (bp[i].param == num) {
                curmode=MODE_NONE;
                break_continuing=1;
                break_stopped=1;
                break_sendentity();
                //FIXME: 64bit
                //FIXME: hardcoded?!?  more than 300+ for i386
                sprintf(buf,">> SYSCALL breakpoint #%d [%d, %s] stop at 0x%llx [%s].\n",i,num,scnames[num & 0xff],r.rip,break_getname(r.rip));
                send_asynctext(buf);
            }

    if (curmode == MODE_SYSCALL) {
        curmode=MODE_NONE;
        break_continuing=1;
        break_stopped=1;
        break_sendentity();
        //FIXME: 64bit
        //FIXME: hardcoded?!?  more than 300+ for i386
        sprintf(buf,">> Syscall %d (%s) reached at 0x%llx [%s].\n",num,scnames[num & 0xff],r.rip,break_getname(r.rip));
        send_asynctext(buf);
    }

}

void break_call(unsigned int addr) {
    char buf[1000];
    if (curmode == MODE_CALL) {
        curmode=MODE_NONE;
        break_continuing=1;
        break_stopped=1;
        break_sendentity();
        //FIXME: 64bit
        sprintf(buf,">> Local call to 0x%x reached at 0x%llx [%s].\n",addr,r.rip,break_getname(r.rip));
        send_asynctext(buf);
    }
}

void break_ret(void) {
    char buf[1000];
    if (curmode == MODE_RET) {
        modepar--;
        if (modepar<=0) {
            curmode=MODE_NONE;
            break_continuing=1;
            break_stopped=1;
            break_sendentity();
            //FIXME: 64bit
            sprintf(buf,">> RET stop point reached at 0x%llx [%s].\n",r.rip,break_getname(r.rip));
            send_asynctext(buf);
        }
    }
}

void break_nestdown(void) {
    char buf[1000];
    if (curmode == MODE_NEST) {
        if (current->nest < modepar) {
            curmode=MODE_NONE;
            break_continuing=1;
            break_stopped=1;
            break_sendentity();
            //FIXME: 64bit
            sprintf(buf,">> Logical nesting stop point reached at 0x%llx [%s].\n",r.rip,break_getname(r.rip));
            send_asynctext(buf);
        }
    }
}

void break_enterdyn(void) {
    char buf[1000];
    if (curmode == MODE_DYN) {
        curmode=MODE_NONE;
        break_continuing=1;
        break_stopped=1;
        break_sendentity();
    }
    //FIXME: 64bit
    sprintf(buf,">> Entered main code at 0x%llx [%s].\n",r.rip,break_getname(r.rip));
    send_asynctext(buf);
}

extern unsigned int get_handler(int i);

void break_signal(unsigned int signo) {
    int i;
    char buf[1000];

    for (i=0;i<MAXBREAK;i++)
        if (bp[i].type == BP_SIG)
            if (bp[i].param == signo) {
                curmode=MODE_NONE;
                break_stopped=1;
                break_sendentity();
                //FIXME: 64bit
                sprintf(buf,">> Signal %d breakpoint #%d stop at 0x%llx [%s] (handler 0x%x).\n",signo,i,r.rip,break_getname(r.rip),get_handler(signo));
                send_asynctext(buf);
            }

}

void break_memread(unsigned int addr) {
    // See if we have rwatch on this addr.

    int i;
    char buf[1000];

    for (i=0;i<MAXBREAK;i++)
        if (bp[i].type == BP_R) {

            if ((bp[i].param <= addr) && (bp[i].param2 >= addr)) {
                curmode=MODE_NONE;
                break_continuing=1;
                break_stopped=1;
                break_sendentity();
                //FIXME: 64bit
                sprintf(buf,">> Read watchpoint #%d stop at 0x%llx [%s] (read of 0x%x).\n",i,r.rip,break_getname(r.rip),addr);
                send_asynctext(buf);
            }
        }
}

void break_memwrite(unsigned int addr) {
    // See if we have wwatch on this addr.

    int i;
    char buf[1000];

    for (i=0;i<MAXBREAK;i++)
        if (bp[i].type == BP_W)
            if ((bp[i].param <= addr) && (bp[i].param2 >= addr)) {
                curmode=MODE_NONE;
                break_continuing=1;
                break_stopped=1;
                break_sendentity();
                //FIXME: 64bit
                sprintf(buf,">> Write watchpoint #%d stop at 0x%llx [%s] (read of 0x%x).\n",i,r.rip,break_getname(r.rip),addr);
                send_asynctext(buf);
            }
}

void break_goaway(void) {
    send_synctext("ERROR: I am running in 'no analysis' mode. This feature is not available.\n");
}

void break_tellresumed(void) {
    send_asynctext(">> Previous syscall resumed.\n");
}

void break_tellwillresume(int i) {

    if (i) {
        char buf[1024];
        //FIXME: 64bitmode
        sprintf(buf,"WARNING: This syscall will resume upon continuation. If that is not what you\n"
                "want, type 'setreg rip 0x%llx' and set %%rax to a desired return value.\n",r.rip);
        send_asynctext(buf);
    } else
        send_asynctext("This syscall will be not resumed. You might want to set %rax to a desired\n"
                "return value, or just ignore it.\n");

}
