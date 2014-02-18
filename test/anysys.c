#include <stdlib.h>

// Just call any syscall.

void signalek(int nr,int a, int b)
{
    long __res;
    __asm__ volatile ("int $0x80"
            : "=a" (__res) \
            : "0" (nr), "b" (a), "c" (b));
}

int main(int argc __attribute__((unused)), char* argv[])
{
    signalek(atoi(argv[1]),atoi(argv[2]),atoi(argv[3]));
    return 0;
}
