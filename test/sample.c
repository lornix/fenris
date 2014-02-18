#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Just a sample code for ragnarok.

void innafunkcja(char* x)
{
    strcpy(x,"this is just a test");
}

int main()
{
    char* buf;
    buf=malloc(100);
    bzero(buf,100);
    innafunkcja(buf);
    printf("This is a result: %s\n",buf);
    free(buf);
    return 0;
}
