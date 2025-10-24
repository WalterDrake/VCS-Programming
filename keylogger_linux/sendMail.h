#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

#define SMTP_URL "smtps://smtp.gmail.com:465"
#define USER_EMAIL "dat123mall@gmail.com"
#define USER_PASS "xdqs ophh vpqg htxp"
#define TO_EMAIL "dat1234mall@gmail.com"

static int emailCounter = 1;

void sendMail(const char *zipPath);