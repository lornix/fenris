#include <stdio.h>

// Local symbols test

void dwa(char*  x) { printf("%s\\n",x); }
void trzy(void* x) { printf("%lx\\n",(unsigned long int)x); }

int fiutk;

int main()
{
    printf("Jestem.\n");
    trzy(dwa);
    dwa("malym");
    trzy(dwa);
    trzy(&fiutk);
    return 0;
}
