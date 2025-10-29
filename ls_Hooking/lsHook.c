#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

// Reference: https://infosecwriteups.com/a-gentle-introduction-to-function-hooking-using-ld-preload-1714124a6eb9
//            https://www.netspi.com/blog/technical-blog/network-pentesting/function-hooking-part-i-hooking-shared-library-function-calls-in-linux/

// Compile: gcc -shared -fPIC -o lsHook.so lsHook.c -ldl
// Usage: export LD_PRELOAD=$PWD/lsHook.so

struct dirent *readdir(DIR *dirp)
{
    // function pointer to hold the original readdir function
    static struct dirent *(*origReaddir)(DIR *) = NULL;
    if (!origReaddir)
    {
        // fetch the original readdir function in the dynamic link chain
        origReaddir = dlsym(RTLD_NEXT, "readdir");
        if (!origReaddir)
            return NULL;
    }

    struct dirent *d;
    while ((d = origReaddir(dirp)) != NULL)
    {
        if(strcmp(d->d_name, "walterdrake.txt") == 0 && d->d_type == DT_REG)
            continue;
        return d;
    }
    return NULL;
}
