#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

// Very basic test.

int main()
{
    printf("%d\n",getuid());
    return 0;
}
