/* common defines */
#ifndef HAVE_COMMON_H
#define HAVE_COMMON_H

#define STDERRMSG(x...) fprintf(stderr,x)
#define FATALEXIT(x)    do { STDERRMSG("FATAL: %s\n",x); exit(1); } while (0);
#define PERROREXIT(x)   do ( perror(x); exit(1); } while (0);

#define MAXMYSIG 31

#define MAG      "\\033[0;35m"
#define CYA      "\\033[0;36m"
#define NOR      "\\033[0;37m"
#define DAR      "\\033[1;30m"
#define RED      "\\033[1;31m"
#define GRE      "\\033[1;32m"
#define YEL      "\\033[1;33m"
#define BRI      "\\033[1;37m"


struct my_user_regs_struct
{
  long long int r15;
  long long int r14;
  long long int r13;
  long long int r12;
  long long int rbp;
  long long int rbx;
  long long int r11;
  long long int r10;
  long long int r9;
  long long int r8;
  long long int rax;
  long long int rcx;
  long long int rdx;
  long long int rsi;
  long long int rdi;
  long long int orig_rax;
  long long int rip;
  long long int cs;
  long long int eflags;
  long long int rsp;
  long long int ss;
  long long int fs_base;
  long long int gs_base;
  long long int ds;
  long long int es;
  long long int fs;
  long long int gs;
};

#endif /* HAVE_COMMON_H */
