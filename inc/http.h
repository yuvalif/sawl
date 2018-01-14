#pragma once

// http_process - process HTTP message to extract URL and hostname
// p - pointer to beginning of message
// len - length of message
// hst - return pointer to the host buffer
// hLen - return the length of the hostname
// url - return pointer to the URL buffer
// uLen - return length of URL
// returns - 
// 0 -  was able to extract at least the hostname
// -1 - was not able to extract hostname (and URL)
int http_process(char *p, int len, char** hst, int* hLen, char** url, int* uLen);

