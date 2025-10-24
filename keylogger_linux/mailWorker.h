#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#ifndef MAIL_WORKER_H
#define MAIL_WORKER_H

// Send mail make delayed, so we use a worker thread to handle it

void initMailWorker();
void enqueueMail(const char *zipPath);
void stopMailWorker();

#endif