#include <stdio.h>

// Test pointer-follow function calls detection.

void innafunkcja() { printf("dupa\n"); }

int main()
{
    void (*fn)();
    fn=innafunkcja;
    fn();
    return 0;
}
