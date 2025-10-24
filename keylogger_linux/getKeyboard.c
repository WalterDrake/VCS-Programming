#include "getKeyboard.h"

char *getKeyboard(void)
{
    FILE *fp = fopen("/proc/bus/input/devices", "r");
    if (!fp)
        return NULL;

    static char devicePath[64];
    char line[512];
    char candidateUSB[64] = {0};
    char candidatePS2[64] = {0};
    int isKeyboard = 0;
    int busType = 0;

    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "I:", 2) == 0)
        {
            isKeyboard = 0;
            busType = 0;
        }

        if (strstr(line, "Bus=0003"))
            busType = 3;
        if (strstr(line, "Bus=0011"))
            busType = 11;

        if (strcasestr(line, "keyboard"))
            isKeyboard = 1;

        if (isKeyboard && strstr(line, "Handlers="))
        {
            char *ev = strstr(line, "event");
            if (ev)
            {
                char eventName[32];
                sscanf(ev, "%31s", eventName);

                char path[64];
                snprintf(path, sizeof(path), "/dev/input/%s", eventName);

                if (busType == 3)
                    strncpy(candidateUSB, path, sizeof(candidateUSB));
                else if (busType == 11)
                    strncpy(candidatePS2, path, sizeof(candidatePS2));
            }
        }
    }

    fclose(fp);

    if (candidateUSB[0])
        strncpy(devicePath, candidateUSB, sizeof(devicePath));
    else if (candidatePS2[0])
        strncpy(devicePath, candidatePS2, sizeof(devicePath));
    else
        return NULL;

    return devicePath;
}
