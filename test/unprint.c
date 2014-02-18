#include <sys/stat.h>
#include <fcntl.h>

// Unprintable characters filtering test

int main()
{
    open("/dev/\n\"blah\xff bounc",0);
    return 0;
}
