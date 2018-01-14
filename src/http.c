#include <string.h>
#include <stdlib.h>

#define TEST_OUT_OF_PACKET()  if (p >= pe) {return -1;}

int http_process(char *p, int len, char** hst, int* hLen, char** url, int* uLen)
{
    char *pe = p + len, *p1, *p2;

    *hLen = 0;
    *uLen = 0;
    *hst = NULL;
    if (url)
        *url = NULL;

    // feed the HTTP method
    // I limit myself to GET/POST only
    if (memcmp(p,"GET ",4) == 0)
    {
        p += 4;
    }
    else if (memcmp(p,"POST ",5) == 0)
    {
        p += 5;
    }
    else
    {
        return -1;
    }

    TEST_OUT_OF_PACKET();

    // in case the proxy is used the url starts with host
    // that is the request will look as GET http://www.somehost.com/the/url or with port GET http://www.somehost.com:8080/the/url

    if (strncasecmp(p,"http://",7) == 0)
    {
        p += 7;
        TEST_OUT_OF_PACKET();
        *hst = p;

        p1 = memchr(p,'/',pe-p); // the URL must start with '/'
        if (!p1 || p1 > pe)
        {
            // and if it does not, we fail this packet
            return -1;
        }

        // the URL may be empty, thus ' ' may come before '/'
        p2 = memchr(p,' ',pe-p);
        if (p2 && p2 < p1)
        {
            p1 = p2;
        }

        // p1 - points to the start of URL

        // test whether the port is present, 'p' still points to the start of host name
        p2 = memchr(p,':',pe-p);
        if (p2 && p2 < p1)
        {
            // the port is present, we don't care for its value
            *hLen = p2 - p;
        }
        else 
        {
            *hLen = p1 - p;
        }

        // move 'p' after the host value
        p = p1;
    }

    // the URL may be empty
    if (*p == ' ')
    {
        if (!url)
        {
            if (*hst)
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }

        // in this case the host was already found, and if not we will fail this request
        static char emptyUrl[20] = {'/',0,0,0};
        if (!*hst)
            return -1;
        *url = emptyUrl;
        *uLen = 1;
        return 0;
    }

    // the url must start with '/'
    if (*p != '/')
        return -1;

    // and end with " HTTP/XXX"
    p1 = memchr(p,' ',pe-p);
    if (!p1 || p1 > pe)
    {
        // can't find the end of URL
        return -1;
    }

    if (url)
    {
        // set the last byte at the end of the URL
        *uLen = p1 - p;
        *url = p;

        p2 = memchr(p,',',*uLen);
        if (p2)
            *uLen = p2 - p;
    }
    p = p1+5;

    // if we could already find the hst, we are done
    if (*hst)
    {
        return 0;
    }

    // otherwise iterate on headers and find the 'Host: '

    // get to the CR-LF
    p1 = memchr(p,13,pe-p);
    if (!p1 || p1 + 1 >= pe || p1[1] != 10)
    {
        return -1;
    }
    // and pass it
    p = p1+2;

    while (1)
    {
        // find the next CR-LF
        p2 = memchr(p,13,pe-p);
        if (!p2 || p2 + 1 >= pe || p2[1] != 10)
        {
            break;
        }
        // p2 - points to the next CR-LF

        if (p2 == p)
        {
            // we are after the last header
            break;
        }

        if (strncasecmp(p,"Host: ",6))
        {
            // not the 'Host' header, jump to the next header
            p = p2 + 2;
            continue;
        }

        p += 6;
        TEST_OUT_OF_PACKET();
        *hst = p;

        // test port presence
        p1 = memchr(p,':',p2-p);
        if (p1 && p1 < p2)
        {
            // port was found and it is before the next end-of-line
            *hLen = p1 - p;
        }
        else
        {
            *hLen = p2 - p;
        }

        break;
    }

    if (*hst)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

