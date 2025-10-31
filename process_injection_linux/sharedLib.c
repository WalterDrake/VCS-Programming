#include <stdio.h>

__attribute__((constructor))
static void init() {
    printf("Injected successfully!\n");
}