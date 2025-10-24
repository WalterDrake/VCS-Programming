#include "mailWorker.h"
#include "sendMail.h"

// Maximum number of queued emails
#define MAX_QUEUE 10


static pthread_t mailThread;
static pthread_mutex_t queueLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queueCond = PTHREAD_COND_INITIALIZER;

static char *mailQueue[MAX_QUEUE];
static int queueStart = 0, queueEnd = 0, queueCount = 0;
static int running = 1;

void* mailWorkerLoop(void *arg)
{
    while (1)
    {
        pthread_mutex_lock(&queueLock);
        while (queueCount == 0 && running)
            // Temporarily release lock and sleep
            // Wait for something in the queue or stop signal
            pthread_cond_wait(&queueCond, &queueLock);

        // Exit if stopped and queue is empty
        if (!running && queueCount == 0)
        {
            pthread_mutex_unlock(&queueLock);
            break;
        }

        // Dequeue mail
        char *zipPath = mailQueue[queueStart];
        queueStart = (queueStart + 1) % MAX_QUEUE;
        queueCount--;
        pthread_mutex_unlock(&queueLock);

        sendMail(zipPath);
        free(zipPath);
    }

    return NULL;
}

void initMailWorker()
{
    pthread_create(&mailThread, NULL, mailWorkerLoop, NULL);
}

void enqueueMail(const char *zipPath)
{
    pthread_mutex_lock(&queueLock);

    if (queueCount < MAX_QUEUE)
    {
        mailQueue[queueEnd] = strdup(zipPath);
        queueEnd = (queueEnd + 1) % MAX_QUEUE;
        queueCount++;
        pthread_cond_signal(&queueCond);
    }

    pthread_mutex_unlock(&queueLock);
}

void stopMailWorker()
{
    pthread_mutex_lock(&queueLock);
    running = 0;
    pthread_cond_signal(&queueCond);
    pthread_mutex_unlock(&queueLock);
    pthread_join(mailThread, NULL);
}