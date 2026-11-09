#include <unistd.h>
#include <stdio.h>

int main(void)
{
    puts("ready");
    fflush(stdout);
    sleep(8);
    return 0;
}
