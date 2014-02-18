#include <stdio.h>

// signal() test... erm, I had to use assembly because
// new libc calls rt_sigaction instead :/

void signalek(int a,void* ptr)
{
    long __res;
    __asm__ volatile ("int $0x80"
            : "=a" (__res) \
            : "0" (48), "b" (a), "c" (ptr));
}

void dupajeza()
{
    printf("juhu\n");
}

int main()
{
    signalek(10,dupajeza);
    signalek(10,(void*)123456);
    signalek(10,0);
    signalek(10,(void*)123456);
    return 0;
}
