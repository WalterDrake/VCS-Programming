#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

#define SMTP_URL "smtps://smtp.gmail.com:465"
#define USER_EMAIL "sender@gmail.com"
#define USER_PASS "xxxx xxxx xxxx xxxx"
#define TO_EMAIL "recipient@gmail.com"

static int emailCounter = 1;

void sendMail(const char *zipPath);