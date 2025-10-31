#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

int main(void)
{
    printf("Sample process for injection.\n");
    printf("PID: %d\n", getpid());
    while (1)
    {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        printf("Current time: %02d:%02d:%02d\n", t->tm_hour, t->tm_min, t->tm_sec);
        sleep(1);
    }
    return 0;
}