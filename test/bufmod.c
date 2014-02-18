#include <stdio.h>

void fufkcja(char* b2)
{
    char buf[10];
    buf[2]=12;
    b2[2]=34;
    printf("l0 %lx l-1 %lx\n",(unsigned long int)buf,(unsigned long int)b2);
}

void fuf()
{
    char buf[10];
    buf[1]=1;
    fufkcja(buf);
}

int main()
{
    fuf();
    return 0;
}
