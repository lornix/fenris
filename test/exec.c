#include <unistd.h>

// Test execve() reporting.

int main()
{
    execl("/bin/nonexisting","nope",NULL);
    execl("/bin/ls","ls",NULL);
    return 0;
}
