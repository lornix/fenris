/* common defines */

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
