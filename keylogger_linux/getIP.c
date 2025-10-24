#include "getIP.h"

char *getLocalIP()
{
    static char ip[INET_ADDRSTRLEN] = "Unknown";
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return ip;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    connect(sock, (const struct sockaddr *)&serv, sizeof(serv));

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr *)&name, &namelen);
    inet_ntop(AF_INET, &name.sin_addr, ip, sizeof(ip));

    close(sock);
    return ip;
}

