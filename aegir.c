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

   Well - readline support mindlessly ripped from Argante r1.
   Original code in Argante r1 came from Artur Skura. What is still
   terribly wrong is that async output from Fenris can pop up at any
   time and will make the screen look ugly. Hey, any libreadline wizards?

   For testing, use test/fakedebug.c.

   "dobry feature to feature w wygodnym toolu"
        Slawomir Krawczyk, Dziela zebrane tom XLVII

 */

#include <unistd.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#ifndef UNIX_PATH_MAX           /* max unix socket name length */
#define UNIX_PATH_MAX   108
#endif


#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#include <sched.h>
#endif /* HAVE_READLINE */

#include "config.h"
#include "fdebug.h"
#include "aegir-decl.h"
#include "libdisasm/opcodes2/opdis.h"

#define debug(x...)     fprintf(stderr,x)
#define pfatal(y)       { if (y) perror(y); if (stupid_pid) kill(stupid_pid,15); exit(1); }
#define fatal(x)        { debug("FATAL: %s\n",x); if (stupid_pid) kill(stupid_pid,15); exit(1); }

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

int    stupid_pid;
char   T_besync=1;

struct aegir_cmd {
  char* cmd;
  void (*handler)(char* param);
  char* help;
};

static unsigned char stopped;

char   use_readline,prompted;
char   input_buffer[1024];
char   restart_last;

// For sscanf hack. Blame libc authors.

unsigned long long l1, l2;

#define LC(x) { \
                if (x > 0xffffffff) { debug("Value out of range.\n"); \
                return; } \
              }

// Predefined commands.
struct aegir_cmd cmd[MAXCMD+1] = {
   { "disass",  do_disass,      "disass [ x len ]: disassemble current eip [ or memory region ]" },
   { "regs",    do_regs,        "display registers" },
   { "back",    do_back,        "display call backtrace" },
   { "cur",     do_cur,         "display last line from Fenris" },
   { "info",    do_addr,        "info x: get info about name or address x" },
   { "fdinfo",  do_fd,          "fdinfo x: display info about file descriptor x" },
   { "break",   do_break,       "break x: set a breakpoint at address x" },
   { "sbreak",  do_sbreak,      "break x: set a breakpoint on syscall x" },
   { "ibreak",  do_ibreak,      "break x: set a breakpoint on signal x" },
   { "rwatch",  do_rwatch,      "rwatch x y: watch memory region for reads" },
   { "wwatch",  do_wwatch,      "wwatch x y: watch memory region for writes" },
   { "step",    do_step,        "step [ x ]: do a single step [ or x steps ]" },
   { "ret",     do_ret,         "ret [ x ]: continue until [ x-th ] ret" },
   { "libc",    do_libc,        "continue to next libcall" },
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
   { "del",     do_del,         "del x: delete a watchpoint or breakpoing" },
   { "memmap",  do_memmap,      "display process memory map" },
   { "fdmap",   do_fdmap,       "display process file descriptor map" },
   { "fnmap",   do_fnmap,       "list known local functions" },
   { "signals", do_signals,     "display signal actions" },
   { "load",    load_module,    "load x: load custom debugging module x" },
   { "exec",    exec_cmd,       "exec x: execute shell command x" },
   { "help",	display_help,   "display help" },
   { "?",	display_help,   0 },
   { "quit",	handle_quit,    "quit, exit: terminate the session" },
   { "exit",	handle_quit,    0 }
};



#ifdef HAVE_READLINE


// There is an ugly hack there (and later, with clone()). Basically,
// libreadline is not too good with async reading and such (it is
// theoretically possible, but not always working as we want it). So
// we have to create a new thread and read in sync mode there.

char   *read_stack, *read_tmp;

static int read_the_line(void* arg) {
  char* prev=0;
  signal(SIGINT,SIG_IGN);
  usleep(200000);
  while (1) {
    // It never hurts to wait.
    while (read_tmp) usleep(20000);
    if (prev) free(prev);
    if (!(read_tmp=readline(PROMPT))) {
      debug("Use 'quit yes' (or 'q y') to quit.\n");
    } else if (strlen(read_tmp)) add_history(read_tmp);
    prev=read_tmp;
    kill(getppid(),SIGUSR1);
  }
  return 0;
}

#endif

int hardstopping;

void ctrlc(int x) {
  if (stopped) {
    debug("Use 'quit yes' (or 'q y') to quit.\n");
  } else hardstopping=1;
}
    


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


void register_command(char* commd,void* handler,char* help) {
  int q=0;
  if (!commd) fatal("You cannot register command with null name");
  while (cmd[q].cmd) q++;
  if (q>=MAXCMD) fatal("MAXCMD exceeded");
  cmd[q].cmd=strdup(commd);
  cmd[q].handler=handler;
  cmd[q].help=strdup(help);
}

static char last_buf[MAXFENT];


static void do_cur(char* param) {
  debug("%s",last_buf);
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
  debug("So long, and thanks for all the fish.\n");
#ifdef HAVE_READLINE
  kill(stupid_pid,15);
#endif
  usleep(200000);
  exit(0);
}


// "exec" handler
static void exec_cmd(char* param) {
  if (!param) {
    debug("You have to provide a command to be executed.\n");
    return;
  }
  system(param);
}

// custom fprintf routine, called indirectly from opdis.c
static int aegir_fprintf(FILE *stream, char *format, ...)
{
  va_list args;
  
  va_start(args, format);
  vfprintf(stream, format, args);
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
        debug("Two numeric parameters required.\n");
        return;
      }
      LC(l1); LC(l2);
      st=l1;len=l2;
      if (len<0) {
        debug("Empty range provided.\n");
        return;
      }
    } else {
      if (sscanf(param,"%Li",&l1)!=1) {
        debug("The parameter needs to be an address.\n");
        return;
      }
      LC(l1); 
      st=l1;
      len=0;
    }
  }

  if (len > MAXFENT-30) {
    debug("You exceeded the maximum memory size per single request.\n");
    len=MAXFENT-30;
  }

  par[0]=st; par[1]=st+len+16;

  if (par[0] > par[1]) {
    debug("Illegal combination of start address and length.\n");
    return;
  }

  mem=send_message(DMSG_GETMEM,(char*)&par,0);
  retlen=*((unsigned int*)mem);
  if (retlen<=0) {
    debug("Unable to access memory at 0x%x.\n",st);
    return;
  }
  opdis_disass(stderr, &mem[4], st, len>retlen ? retlen : len);
  fflush(0);
  if (retlen<len)
    debug("Truncated - unable to access memory past 0x%x.\n",st+retlen);
}


// Describe addresses in disassembly. Called from opdis.c.

char descbuf[MAXFENT];

char* describe_address(unsigned int addr) {
  return send_message(DMSG_GETNAME,(char*)&addr,descbuf);
}


// "x" handler
static void do_memdump(char* param) {
  unsigned int st,len;
  char* mem;
  unsigned int par[2];
  int retlen;
  int caddr;
 
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
      st=l1;
      LC(l1);

      len=16;
    }
  }

  if (len > MAXFENT-20) {
    debug("You exceeded the maximum memory size per single request.\n");
    len=MAXFENT-20;
  }


  par[0]=st; par[1]=st+len;

  if (par[0] > par[1]) {
    debug("Illegal combination of start address and length.\n");
    return;
  }


  mem=send_message(DMSG_GETMEM,(char*)&par,0);
  retlen=*((unsigned int*)mem);
  mem+=4;
  if (retlen<=0) {
    debug("Unable to access memory at 0x%x.\n",st);
    return;
  }

  if (retlen>len) retlen=len;

  caddr=0;
  while (caddr<retlen) {
    int i;
    int rem;
    rem=retlen-caddr;
    if (rem>16) rem=16;
    debug("%08x: ",st+caddr);
    for (i=0;i<rem;i++) debug("%02x ",(unsigned char)mem[caddr+i]);
    
    if (rem<16) 
      for (i=0;i<16-rem;i++) debug("   ");
    
    debug(" | ");
    for (i=0;i<rem;i++) debug("%c",isprint(mem[caddr+i])?mem[caddr+i]:'.');
    debug("\n");
    caddr+=16;
  }

  if (retlen<len)
    debug("Truncated - unable to access memory past 0x%x.\n",st+retlen);
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

  debug("eax \t0x%08x\t %d\n",(int)x->eax,(int)x->eax);
  debug("ebx \t0x%08x\t %d\n",(int)x->ebx,(int)x->ebx);
  debug("ecx \t0x%08x\t %d\n",(int)x->ecx,(int)x->ecx);
  debug("edx \t0x%08x\t %d\n",(int)x->edx,(int)x->edx);
  debug("esi \t0x%08x\t %d\n",(int)x->esi,(int)x->esi);
  debug("edi \t0x%08x\t %d\n",(int)x->edi,(int)x->edi);
  debug("ebp \t0x%08x\t %d\n",(int)x->ebp,(int)x->ebp);
  debug("esp \t0x%08x\t %d\n",(int)x->esp,(int)x->esp);
  debug("eip \t0x%08x\t %d\n",(int)x->eip,(int)x->eip);
  debug("eflags \t0x%08x\t 0%o\n",(int)x->eflags,(int)x->eflags);
  debug("ds \t0x%x\n",(int)x->xds);
  debug("es \t0x%x\n",(int)x->xes);
  debug("fs \t0x%x\n",(int)x->xfs);
  debug("gs \t0x%x\n",(int)x->xgs);
  debug("cs \t0x%x\n",(int)x->xes);
  debug("ss \t0x%x\n",(int)x->xss);

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
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.eax,val);
    x.eax=val;
  } else

  if (!strcasecmp("ebx",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.ebx,val);
    x.ebx=val;
  } else

  if (!strcasecmp("ecx",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.ecx,val);
    x.ecx=val;
  } else

  if (!strcasecmp("edx",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.edx,val);
    x.edx=val;
  } else

  if (!strcasecmp("esi",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.esi,val);
    x.esi=val;
  } else

  if (!strcasecmp("edi",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.edi,val);
    x.edi=val;
  } else

  if (!strcasecmp("esp",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.esp,val);
    x.esp=val;
  } else

  if (!strcasecmp("eip",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.eip,val);
    debug("Note: modifying eip is the best way to trash Fenris. Act wisely.\n");
    x.eip=val;
  } else

  if (!strcasecmp("ebp",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.ebp,val);
    x.ebp=val;
  } else

  if (!strcasecmp("eflags",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.eflags,val);
    x.eflags=val;
  } else

  if (!strcasecmp("ds",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.xds,val);
    x.xds=val;
  } else

  if (!strcasecmp("es",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.xes,val);
    x.xes=val;
  } else

  if (!strcasecmp("fs",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.xfs,val);
    x.xfs=val;
  } else

  if (!strcasecmp("gs",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.xgs,val);
    x.xgs=val;
  } else

  if (!strcasecmp("cs",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.xcs,val);
    x.xcs=val;
  } else

  if (!strcasecmp("ss",regname)) {
    debug("Changing %s from 0x%x to 0x%x...\n",regname,(int)x.xss,val);
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
      debug("%s",(char*)x);
    }
  } else {
    st=l1;
    LC(l1); 
    x=(void*)send_message(DMSG_DESCADDR,&st,0);
    debug("%s",(char*)x);
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







static unsigned int sd;

static void connect_to_fenris(char* where) {
  struct sockaddr_un sun;

  debug("[+] Connecting to Fenris at %s...\n",where);

  if ((sd = socket (AF_LOCAL, SOCK_STREAM, 0))<0) {
    pfatal("cannot create a socket");
    exit(1); 
  }

  sun.sun_family = AF_LOCAL;
  strncpy (sun.sun_path, where, UNIX_PATH_MAX);
  if (connect (sd, (struct sockaddr*)&sun,sizeof (sun))) {
    pfatal("cannot connect to Fenris socket");
    exit(1);
  }

  debug("[+] Trying to send \"hello\" message...\n");
  send_message(DMSG_FOO,0,0);
  debug("[*] Response ok, connection established.\n\n");

}

static char str_buf[MAXFENT];

static char* get_string_sock(int sock) {
  char t[2];
  t[1]=0;
  str_buf[0]=0;
  fcntl(sock,F_SETFL,O_SYNC);
  while (1) {
    if (read(sock,t,1)!=1) 
      fatal("short read in get_string_sock from Fenris");
    if (!t[0]) {
      fcntl(sock,F_SETFL,O_NONBLOCK);
      return str_buf;
    }
    strcat(str_buf,t);
    if (strlen(str_buf)>=sizeof(str_buf)-2)
      fatal("string from Fenris is of excessive length");
  }
  fatal("Another broken Turing machine. Rhubarb.");
}

static int get_dword_sock(int sock) {
  int ret=0;
  fcntl(sock,F_SETFL,O_SYNC);
  if (read(sock,&ret,4)!=4) fatal("short read in get_dword_sock in Fenris");
  fcntl(sock,F_SETFL,O_NONBLOCK);
  return ret;
}

int prevstopped,please_dis;


static char msg_data[MAXFENT];
static char async_buf[MAXFENT];

int doingstop;

void* send_message(int mtype,void* data,void* store) {
  struct dmsg_header x;
  int dlen=0;
  int got_sync;

  if (stopped) doingstop=0;

  if (hardstopping) {
    hardstopping=0;
    doingstop++;
    switch (doingstop) {
      case 1: do_stop(0); break;
      case 2: do_halt(0); break;
      // default: /* duh! */
    }
  }

  if (!store) store=msg_data;

  switch (mtype) {

    case DMSG_NOMESSAGE: break; /* don't send, just check async */

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

  fcntl(sd,F_SETFL,O_NONBLOCK);

  got_sync=0;
  
read_loop:

  errno=0;

  bzero(&x,sizeof(x));

  if (read(sd,&x,sizeof(x))!=sizeof(x)) {
    if (errno!=EAGAIN) {
      debug("%s",async_buf);
      fatal("disconnected from Fenris");
    } else goto nothing_to_read;
  }

  if (x.magic1 != DMSG_MAGIC1) fatal("incorrect magic1 from Fenris");
  if (x.magic2 != DMSG_MAGIC2) fatal("incorrect magic2 from Fenris");


  prevstopped=stopped;
  stopped=!(x.code_running);

  if (stopped && !prevstopped) please_dis=1;

  if (x.type == DMSG_ASYNC) {
    char* x=get_string_sock(sd);

    if (strlen(async_buf)+strlen(x)>=sizeof(async_buf)-1)
      fatal("async entity too long");
    strcat(async_buf,x);

    if (restart_last) {
      last_buf[0]=0; restart_last=0;
    }

    if (strlen(last_buf)+strlen(x)>=sizeof(last_buf)-1)
      fatal("async entity too long [2]");
    strcat(last_buf,x);

  } else {
    int a,b;

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
        fcntl(sd,F_SETFL,O_SYNC);
        while (b<a) {
          int inc;
          inc=read(sd,&((char*)store)[4+b],a-b);
          if (inc<=0) fatal("short read on DMSG_GETMEM");
          b+=inc;
        }
        fcntl(sd,F_SETFL,O_NONBLOCK);
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
        fcntl(sd,F_SETFL,O_SYNC);
        if (read(sd,store,sizeof(struct user_regs_struct))!=
            sizeof(struct user_regs_struct))
            fatal("short read on DMSG_RETREGS");
        fcntl(sd,F_SETFL,O_NONBLOCK);
        break;

      // Empty.
      case DMSG_FOO:  break;
 
      // Catch whatever I missed...
      default: fatal("implementation error in send_message");

    }

    // Don't exit immediately, be sure to fetch pending ASYNCs.
    got_sync=1;
  }

  goto read_loop;

nothing_to_read:

  if ((mtype != DMSG_NOMESSAGE) && (!got_sync)) goto read_loop;
  fcntl(sd,F_SETFL,O_SYNC);

  if (got_sync) return store; else return 0;

}


char* check_async(void) {
  return async_buf;
}


void destroy_async(void) { 
  async_buf[0]=0;
}


void wait_for_stopped(void) { 
  do {
    fd_set f;
    FD_ZERO(&f);
    FD_SET(sd,&f);
    select(sd+1,&f,0,&f,0);
    send_message(DMSG_NOMESSAGE,0,0);
  } while (!stopped);
}


void donothing(int x) { 
}

static void usage(char *name) {
  debug("Usage: %s [ -i ] [%%]/path/to/fenris-socket\n\n",name);
  debug("This program is a companion interface for Fenris. Fenris has to be launched\n"
        "with -W option prior to executing this code. If Fenris is running right now,\n"
        "please call this program again, providing the socket filename as a parameter.\n"
        "This can be an arbitrary filename in a directory you have write access to.\n\n"
        "Adding -i option when invoking aegir sets Intel notation for disassembly.\n\n"
        "Adding '%%' before the filename will cause Aegir to run in asynchronous command\n"
        "mode (which is a bit experimental).\n\n");
  exit(1);
}


int main(int argc,char* argv[]) {

  char opt;
  char T_intel=0;
  char* fname;
  opdis_options opdis_options;

  signal(SIGUSR1,SIG_IGN);

  while ((opt = getopt(argc, argv, "+i")) != -1)
    switch (opt) {
      case 'i':
        T_intel=1;
	break;
      default:
        usage(argv[0]);
    };

  if (argc-optind<1) usage(argv[0]);

  fname=argv[optind];
  if (*fname=='%') { T_besync=0; fname++; }

  opdis_options.print_func=(opdis_print_func)aegir_fprintf;
  opdis_options.notation=T_intel ? DIS_NOTN_ATT : DIS_NOTN_INTEL;
  opdis_init(&opdis_options);

  connect_to_fenris(fname);


  debug(".---------------------------------------------------------------------.\n"
        "|     -= Welcome to aegir - an interactive debugger for Fenris! =-    |\n"
        "|---------------------------------------------------------------------|\n"
        "|   Copyright (C) 2002 by Michal Zalewski <lcamtuf@bos.bindview.com>  |\n"
        "|    This is a free software and comes with absolutely no warranty.   |\n"
        "| Use \"help\" to get help, and /usr/bin/fenris-bug to report problems. |\n"
        "`---------------------------------------------------------------------'\n\n");

#ifdef HAVE_READLINE
  use_readline=isatty(0);

  if (use_readline) {
    using_history();
    read_stack=(char*)malloc(200000)+100000;
    stupid_pid=clone(read_the_line,read_stack,CLONE_VM,0);
  }

#endif /* HAVE_READLINE */

  while (1) {
    char* i_command;

    // Print out whatever Fenris wants to tell us.
    send_message(DMSG_NOMESSAGE,0,0);

    if (async_buf[0]) {
      debug("%s",async_buf);
      async_buf[0]=0;
    }

    input_buffer[0]=0;

    if (T_besync && please_dis) { please_dis=0; do_disass(0); }

    // Monitor stdin and fenris    
#ifdef HAVE_READLINE
    if (!read_tmp) 
#endif 
    {
      struct sigaction a;
      fd_set f;
      FD_ZERO(&f); 
      FD_SET(sd,&f);
      FD_SET(0,&f);
      bzero(&a,sizeof(a));
      a.sa_handler=donothing;
      sigaction(SIGUSR1,&a,0);
      bzero(&a,sizeof(a));
      a.sa_handler=ctrlc;
      sigaction(SIGINT,&a,0);
      select(sd+1,&f,0,&f,0);
      if (hardstopping) continue;
      signal(SIGUSR1,SIG_IGN);
      signal(SIGINT,ctrlc);
    }

#ifdef HAVE_READLINE
    if (stopped && read_tmp && !strcmp(read_tmp,".lock")) {
      read_tmp=0;
      input_buffer[0]=0;
    }
#endif /* HAVE_READLINE */
    

    if (!T_besync || stopped) {

#ifdef HAVE_READLINE
      if (use_readline) {
        if (read_tmp) {
          if (strlen(read_tmp)) {
            strncpy(input_buffer,read_tmp,sizeof(input_buffer)-1);
          } 
          read_tmp=0;
        } 
      } else
#endif /* HAVE_READLINE */
      {
         int x;
         fcntl(0,F_SETFL,O_NONBLOCK);
         if (!prompted) {
           debug(PROMPT);
           prompted=1;
         }
         x=read(0,input_buffer,sizeof(input_buffer)-1);
         if (x>0) prompted=input_buffer[x]=0;
      }

    }
 
    // Oh geez. User input? Users are obsolete.

    while (strlen(input_buffer) && strchr("\n\r\t ",input_buffer[strlen(input_buffer)-1])) 
      input_buffer[strlen(input_buffer)-1]=0;

    i_command=input_buffer;
    if (!strcmp(i_command,".lock")) continue;

    // Ehh, strchr for character \0 is kinda stupid ;-)
    while (*i_command && strchr("\n\r\t ",*i_command)) i_command++;

    if (strlen(i_command)) {
      char main_cmd[512];
      char matches[1024]; 
      char* f=main_cmd;
      int q=0,got=0;
      struct aegir_cmd* cmptr=0;
      strncpy(main_cmd,i_command,sizeof(main_cmd)-1);
      main_cmd[sizeof(main_cmd)-1]=0;
      while (*f && *f!=' ') f++;
      *f=0;
      restart_last=1;

#ifdef HAVE_READLINE
      read_tmp=".lock";
#endif
      matches[0]=0;

      while (cmd[q].cmd) {
        if (!strncasecmp(main_cmd,cmd[q].cmd,strlen(main_cmd))) {
          got++; cmptr=&cmd[q]; 
          if (matches[0]) strcat(matches,", ");
          // Gee, if you overflow it, it is your fault.
          strcat(matches,cmd[q].cmd);
	}
        q++;
      }

      if (got>1) debug("Ambigious command. Matches: %s\n",matches); 
      else if (got==0) debug("Command '%s' unrecognized. Try 'help' for help.\n",main_cmd);
      else { 
        if (!stopped) debug("WARNING: the code is still running!\n");
        // Well, there is one match.
        i_command=strchr(i_command,' ');
        if (i_command) 
          while (*i_command && strchr("\n\r\t ",*i_command)) i_command++;
        if (cmptr->handler) {
          cmptr->handler(i_command);
          if (T_besync && please_dis) { please_dis=0; do_disass(0); }
        } else debug("This command is not yet implemented.\n");
      }

#ifdef HAVE_READLINE
      if (!T_besync || stopped) read_tmp=0;
#endif
    }
  }

}

