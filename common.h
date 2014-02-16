/* common defines */

#define debug(x...) fprintf(ostream,x)
#define debug(x...) my_wprintw(Waegir,x)
#define debug(x...) wprintw(Waegir,x)

#define STDERRMSG(x...) fprintf(stderr,x)
#define FATALEXIT(x)    do { STDERRMSG("FATAL: %s\n",x); exit(1); } while (0);
#define PERROREXIT(x)   do ( perror(x); exit(1); } while (0);
