#include <unistd.h>

// trivial fork tracing.

int main()
{
    int i;
    i=fork();
    sleep(10);
    sleep(10);
    sleep(10);
    sleep(10);
    sleep(10);
    // if (!i) {
    //     execl("/bin/ls","ls",NULL);
    // }
    i=i;
    return 0;
}

