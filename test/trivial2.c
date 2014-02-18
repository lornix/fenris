#include <unistd.h>
#include <sys/types.h>
// Test parameter counting and such.

int main()
{
    int q;
    // q=getuid(1,2,3);
    // q=getuid(1,2,3);
    q=getuid();
    q=getuid();
    q=q;
    return 0;
}
