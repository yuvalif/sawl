/*
 * http.c
 *
 *  Created on: Jun 17, 2011
 *      Author: chenxm
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "http.h"
#include "radius.h"

#if 0
static const char*
find_line_end(const char *data, const char *dataend, const char **eol);
static int
get_token_len(const char *linep, const char *lineend, const char **next_token);
static char*
find_header_end(const char *data, const char *dataend, int *line_cnt);

/*
 * HTTP status code.
 */
http_st_code HTTP_STATUS_CODE_ARRAY[] = {
    {100, HTTP_ST_100},
    {101, HTTP_ST_101},
    {102, HTTP_ST_102},
    {199, HTTP_ST_199},

    {200, HTTP_ST_200},
    {201, HTTP_ST_201},
    {202, HTTP_ST_202},
    {203, HTTP_ST_203},
    {204, HTTP_ST_204},
    {205, HTTP_ST_205},
    {206, HTTP_ST_206},
    {207, HTTP_ST_207},
    {299, HTTP_ST_299},

    {300, HTTP_ST_300},
    {301, HTTP_ST_301},
    {302, HTTP_ST_302},
    {303, HTTP_ST_303},
    {304, HTTP_ST_304},
    {305, HTTP_ST_305},
    {307, HTTP_ST_307},
    {399, HTTP_ST_399},

    {400, HTTP_ST_400},
    {401, HTTP_ST_401},
    {402, HTTP_ST_402},
    {403, HTTP_ST_403},
    {404, HTTP_ST_404},
    {405, HTTP_ST_405},
    {406, HTTP_ST_406},
    {407, HTTP_ST_407},
    {408, HTTP_ST_408},
    {409, HTTP_ST_409},
    {410, HTTP_ST_410},
    {411, HTTP_ST_411},
    {412, HTTP_ST_412},
    {413, HTTP_ST_413},
    {414, HTTP_ST_414},
    {415, HTTP_ST_415},
    {416, HTTP_ST_416},
    {417, HTTP_ST_417},
    {422, HTTP_ST_422},
    {423, HTTP_ST_423},
    {424, HTTP_ST_424},
    {499, HTTP_ST_499},

    {500, HTTP_ST_500},
    {501, HTTP_ST_501},
    {502, HTTP_ST_502},
    {503, HTTP_ST_503},
    {504, HTTP_ST_504},
    {505, HTTP_ST_505},
    {507, HTTP_ST_507},
    {599, HTTP_ST_599}
};

char *HTTP_METHOD_STRING_ARRAY[] = {
    "OPTIONS",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "TRACE",
    "CONNECT",
    "PATCH",
    "LINK",
    "UNLINK",
    "PROPFIND",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "POLL",
    "BCOPY",
    "BMOVE",
    "SEARCH",
    "BDELETE",
    "PROPPATCH",
    "BPROPFIND",
    "BPROPPATCH",
    "LABEL",
    "MERGE",
    "REPORT",
    "UPDATE",
    "CHECKIN",
    "CHECKOUT",
    "UNCHECKOUT",
    "MKACTIVITY",
    "MKWORKSPACE",
    "VERSION-CONTROL",
    "BASELINE-CONTROL",
    "NOTIFY",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "ICY",
    "NONE"
};

/*
 * To identify if the packet is carrying HTTP request message.
 * If it's true, the head end char pointer will be returned, else NULL.
 */
char*
request_header_end(const char *ptr, const int datalen)
{
    http_mthd method = HTTP_MT_NONE;
    char *head_end = NULL;

    method = http_request_method(ptr, datalen);
    if (method == HTTP_MT_NONE){
        return NULL;
    }
    else{
        int line_cnt = 0;
        head_end = find_header_end(ptr, (ptr+datalen-1), &line_cnt);
        return head_end;
    }
}
/*
 * To identify if the packet is carrying HTTP response message.
 * If it's true, the head end char pointer will be returned, else NULL.
 */
char*
response_header_end(const char *ptr, const int datalen)
{
    http_ver version = HTTP_VER_NONE;
    char *head_end = NULL;

    if (datalen < 8){
        return NULL;
    }

    version = http_response_version(ptr, datalen);
    if (version == HTTP_VER_NONE){
        return NULL;
    }
    else{
        int line_cnt = 0;
        head_end = find_header_end(ptr, (ptr+datalen-1), &line_cnt);
        return head_end;
    }
}

/*
 * From xplico.
 * Given a pointer into a data buffer, and to the end of the buffer,
 * find the end of the line at that position in the data
 * buffer.
 * Return a pointer to the EOL character(s) in "*eol", which is the first of
 * EOL character(s).
 */
static const char*
find_line_end(const char *data, const char *dataend, const char **eol)
{
    const char *lineend;

    lineend = memchr(data, '\n', dataend - data + 1);

    if (lineend == NULL) {
        /*
         * No LF - line is probably continued in next TCP segment.
         */
        lineend = dataend;
        *eol = dataend;
    } else {
        /*
         * Is the LF at the beginning of the line?
         */
        if (lineend > data) {
            /*
             * No - is it preceded by a carriage return?
             * (Perhaps it's supposed to be, but that's not guaranteed....)
             */
            if (*(lineend - 1) == '\r') {
                /*
                 * Yes.  The EOL starts with the CR.
                 */
                *eol = lineend - 1;

            } else {
                /*
                 * No.  The EOL starts with the LF.
                 */
                *eol = lineend;

                /*
                 * I seem to remember that we once saw lines ending with LF-CR
                 * in an HTTP request or response, so check if it's *followed*
                 * by a carriage return.
                 */
                if (lineend < (dataend - 1) && *(lineend + 1) == '\r') {
                    /*
                     * It's <non-LF><LF><CR>; say it ends with the CR.
                     */
                    lineend++;
                }
            }
        } else {

            /*
             * Yes - the EOL starts with the LF.
             */
            *eol = lineend;
        }
    }
    return lineend;
}

/*
 * From xplico.
 * Get the length of the next token in a line, and the beginning of the
 * next token after that (if any).
 * Return 0 if there is no next token.
 */
static int
get_token_len(const char *linep, const char *lineend, const char **next_token)
{
    const char *tokenp;
    int token_len;

    tokenp = linep;

    /*
     * Search for a blank, a CR or an LF, or the end of the buffer.
     */
    while (linep < lineend && *linep != ' ' && *linep != '\r' && *linep != '\n')
        linep++;
    token_len = linep - tokenp;

    /*
     * Skip trailing blanks.
     */
    while (linep < lineend && *linep == ' ')
        linep++;

    *next_token = linep;

    return token_len;
}

/*
 * From xplico.
 * Given a pointer into a data buffer and the length of buffer,
 * find the header end.
 * Return a pointer to the end character of header
 */
static char*
find_header_end(const char *data, const char *dataend, int *line_cnt)
{
    const char *lf, *nxtlf, *end;

    end = NULL;
    lf =  memchr(data, '\n', (dataend - data + 1));
    if (lf == NULL)
        return NULL;
    (*line_cnt)++;
    lf++; /* next character */
    nxtlf = memchr(lf, '\n', (dataend - lf + 1));
    while (nxtlf != NULL) {
        if (nxtlf-lf < 2) {
            end = nxtlf;
            break;
        }
        (*line_cnt)++;
        nxtlf++;
        lf = nxtlf;
        nxtlf = memchr(nxtlf, '\n', dataend - nxtlf + 1);
    }
    return (char *)end;
}

/*
 * From xplico.
 * Get HTTP request method by parsing header line.
 */
http_mthd
http_request_method(const char *data, int linelen)
{
    const char *ptr;
    int index = 0;
    int prefix_len = 0;

    /*
     * From RFC 2774 - An HTTP Extension Framework
     *
     * Support the command prefix that identifies the presence of
     * a "mandatory" header.
     */
    if (linelen >= 2) {
        if (strncmp(data, "M-", 2) == 0 || strncmp(data, "\r\n", 2) == 0) { /* \r\n necesary for bug in client POST */
            data += 2;
            linelen -= 2;
            prefix_len = 2;
        }
    }

    /*
     * From draft-cohen-gena-client-01.txt, available from the uPnP forum:
     *  NOTIFY, SUBSCRIBE, UNSUBSCRIBE
     *
     * From draft-ietf-dasl-protocol-00.txt, a now vanished Microsoft draft:
     *  SEARCH
     */
    ptr = (const char *)data;
    /* Look for the space following the Method */
    while (index < linelen) {
        if (*ptr == ' ')
            break;
        else {
            ptr++;
            index++;
        }
    }

    /* Check the methods that have same length */
    switch (index) {
    case 3:
        if (strncmp(data, "GET", index) == 0) {
            return HTTP_MT_GET;
        }
        else if (strncmp(data, "PUT", index) == 0) {
            return HTTP_MT_PUT;
        }
#if 0
    else if (strncmp(data, "ICY", index) == 0) {
            return HTTP_MT_ICY;
        }
#endif
        break;

    case 4:
        if (strncmp(data, "COPY", index) == 0) {
            return HTTP_MT_COPY;
        }
        else if (strncmp(data, "HEAD", index) == 0) {
            return HTTP_MT_HEAD;
        }
        else if (strncmp(data, "LOCK", index) == 0) {
            return HTTP_MT_LOCK;
        }
        else if (strncmp(data, "MOVE", index) == 0) {
            return HTTP_MT_MOVE;
        }
        else if (strncmp(data, "POLL", index) == 0) {
            return HTTP_MT_POLL;
        }
        else if (strncmp(data, "POST", index) == 0) {
            return HTTP_MT_POST;
        }
        break;

    case 5:
        if (strncmp(data, "BCOPY", index) == 0) {
            return HTTP_MT_BCOPY;
        }
        else if (strncmp(data, "BMOVE", index) == 0) {
            return HTTP_MT_BMOVE;
        }
        else if (strncmp(data, "MKCOL", index) == 0) {
            return HTTP_MT_MKCOL;
        }
        else if (strncmp(data, "TRACE", index) == 0) {
            return HTTP_MT_TRACE;
        }
        else if (strncmp(data, "LABEL", index) == 0) {  /* RFC 3253 8.2 */
            return HTTP_MT_LABEL;
        }
        else if (strncmp(data, "MERGE", index) == 0) {  /* RFC 3253 11.2 */
            return HTTP_MT_MERGE;
        }
        break;

    case 6:
        if (strncmp(data, "DELETE", index) == 0) {
            return HTTP_MT_DELETE;
        }
        else if (strncmp(data, "SEARCH", index) == 0) {
            return HTTP_MT_SEARCH;
        }
        else if (strncmp(data, "UNLOCK", index) == 0) {
            return HTTP_MT_UNLOCK;
        }
        else if (strncmp(data, "REPORT", index) == 0) {  /* RFC 3253 3.6 */
            return HTTP_MT_REPORT;
        }
        else if (strncmp(data, "UPDATE", index) == 0) {  /* RFC 3253 7.1 */
            return HTTP_MT_UPDATE;
        }
        else if (strncmp(data, "NOTIFY", index) == 0) {
            return HTTP_MT_NOTIFY;
        }
        break;

    case 7:
        if (strncmp(data, "BDELETE", index) == 0) {
            return HTTP_MT_BDELETE;
        }
        else if (strncmp(data, "CONNECT", index) == 0) {
            return HTTP_MT_CONNECT;
        }
        else if (strncmp(data, "OPTIONS", index) == 0) {
            return HTTP_MT_OPTIONS;
        }
        else if (strncmp(data, "CHECKIN", index) == 0) {  /* RFC 3253 4.4, 9.4 */
            return HTTP_MT_CHECKIN;
        }
        break;

    case 8:
        if (strncmp(data, "PROPFIND", index) == 0) {
            return HTTP_MT_PROPFIND;
        }
        else if (strncmp(data, "CHECKOUT", index) == 0) { /* RFC 3253 4.3, 9.3 */
            return HTTP_MT_CHECKOUT;
        }
        /*
        else if (strncmp(data, "CCM_POST", index) == 0) {
            return HTTP_MT_CCM_POST;
        }
        */
        break;

    case 9:
        if (strncmp(data, "SUBSCRIBE", index) == 0) {
            return HTTP_MT_SUBSCRIBE;
        }
        else if (strncmp(data, "PROPPATCH", index) == 0) {
            return HTTP_MT_PROPPATCH;
        }
        else  if (strncmp(data, "BPROPFIND", index) == 0) {
            return HTTP_MT_BPROPFIND;
        }
        break;

    case 10:
        if (strncmp(data, "BPROPPATCH", index) == 0) {
            return HTTP_MT_BPROPPATCH;
        }
        else if (strncmp(data, "UNCHECKOUT", index) == 0) {  /* RFC 3253 4.5 */
            return HTTP_MT_UNCHECKOUT;
        }
        else if (strncmp(data, "MKACTIVITY", index) == 0) {  /* RFC 3253 13.5 */
            return HTTP_MT_MKACTIVITY;
        }
        break;

    case 11:
        if (strncmp(data, "MKWORKSPACE", index) == 0) {  /* RFC 3253 6.3 */
            return HTTP_MT_MKWORKSPACE;
        }
        else if (strncmp(data, "UNSUBSCRIBE", index) == 0) {
            return HTTP_MT_UNSUBSCRIBE;
        }
        /*
        else if (strncmp(data, "RPC_CONNECT", index) == 0) {
            return HTTP_MT_RPC_CONNECT;
        }
        */
        break;

    case 15:
        if (strncmp(data, "VERSION-CONTROL", index) == 0) {  /* RFC 3253 3.5 */
            return HTTP_MT_VERSION_CONTROL;
        }
        break;

    case 16:
        if (strncmp(data, "BASELINE-CONTROL", index) == 0) {  /* RFC 3253 12.6 */
            return HTTP_MT_BASELINE_CONTROL;
        }
        break;

    default:
        break;
    }

    return HTTP_MT_NONE;
}

/*
 * From xplico.
 * Get HTTP request URI by parsing header line.
 * Return NULL if no URI found.
 */
char*
http_request_uri(const char *line, int len, unsigned long max_uri_len)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;
    char *uri;

    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return NULL;
    }
    line = next_token;

    /* The next token is the URI. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return NULL;

    /* make sure uri is not more than max */
    if (max_uri_len != 0 && (unsigned int) tokenlen > max_uri_len)
    {
        tokenlen = max_uri_len;
    }
    uri = (char*)malloc(tokenlen+1);
    if (uri != NULL) {
        memcpy(uri, line, tokenlen);
        uri[tokenlen] = '\0';
    }

    return uri;
}

/*
 * From xplico.
 * Get HTTP request version by parsing header line.
 */
http_ver
http_request_version(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;

    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return HTTP_VER_NONE;
    }
    line = next_token;

    /* The next token is the URI. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return HTTP_VER_NONE;
    line = next_token;

    /* Everything to the end of the line is the version. */
    tokenlen = lineend - line;
    if (tokenlen == 0)
        return HTTP_VER_NONE;

    if (strncmp(line, "HTTP/1.0", 8) == 0)
        return HTTP_VER_1_0;

    if (strncmp(line, "HTTP/1.1", 8) == 0)
        return HTTP_VER_1_1;

    return HTTP_VER_NONE;
}


/*
 * From xplico.
 * Get HTTP response version by parsing header line.
 */
http_ver
http_response_version(const char *line, int len)
{
    if (strncmp(line, "HTTP/1.0", 8) == 0)
        return HTTP_VER_1_0;

    if (strncmp(line, "HTTP/1.1", 8) == 0)
        return HTTP_VER_1_1;

    return HTTP_VER_NONE;
}

/*
 * From xplico.
 * Get the HTTP response status code by parsing header line.
 */
http_status
http_response_status(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    http_status status;
    int tokenlen, val;
    int i, dim = sizeof(HTTP_STATUS_CODE_ARRAY)/sizeof(http_st_code);

    lineend = line + len;
    status = HTTP_ST_NONE;

    /* The first token is the protocol and version */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return status;
    }

    line = next_token;
    /* The next token is status value. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || (line[tokenlen] != ' ' && line[tokenlen] != '\r' && line[tokenlen] != '\n')) {
        return status;
    }

    /*
     * Parse response status value.
     */
    if (sscanf(line, "%i", &val) != 1) {
        return status;
    }

    /* search enum */
    for (i=0; i<dim; i++) {
        if (HTTP_STATUS_CODE_ARRAY[i].num == val) {
            status = HTTP_STATUS_CODE_ARRAY[i].st;

            break;
        }
    }
    return status;
}

/*
 * From xplico.
 * Parse header parameter from HTTP header fields.
 * Return the pointer to the parameter value if found;
 * else return NULL.
 */
char*
http_header_param(const char *header, int hlen, const char *param)
{
    const char *line, *eol, *lineend, *hend, *c;
    char *ret;
    int len, host_len, param_len;

    hend = header + hlen - 1;
    line = header;
    len = hlen;
    ret = NULL;
    lineend = NULL;
    param_len = strlen(param);
    while (lineend < hend) {
        lineend = find_line_end(line, line+len-1, &eol);
        if (lineend != hend && (*eol == '\r' || *eol == '\n')) {
            if (strncasecmp(line, param, param_len) == 0) {
                c = line + param_len;
                while (*c == ' ' && c < lineend)
                    c++;
                /*
                 * Move the EOL pointer to the last none-LFCR character.
                 */
                while ( (*eol == '\r' || *eol == '\n') && eol > c)
                    eol--;
                host_len = eol - c + 1;
                ret = (char*)malloc(host_len + 1);
                memset(ret, '\0', host_len + 1);
                memcpy(ret, c, host_len);
                break;
            }
        }
        line = lineend + 1;
        len = hend - lineend;
    }
    return ret;
}
#endif

int http_process(char *p, int len, char** hst, int* hLen, char** url, int* uLen)
{
    char *pe = p + len, *p1, *p2;
    #define TEST_OUT_OF_PACKET()  if (p >= pe) {return -1;}

    *hLen = 0;
    *uLen = 0;
    *hst = NULL;
    if (url)
        *url = NULL;

// feed the HTTP method
// I limit myself to GET/POST only
    if (memcmp(p,"GET ",4) == 0)
        p += 4;
    else if (memcmp(p,"POST ",5) == 0)
        p += 5;
    else
        return -1;

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
            p1 = p2;

        // p1 - points to the start of URL


        // test whether the port is present, 'p' still points to the start of host name
        p2 = memchr(p,':',pe-p);
        if (p2 && p2 < p1)
        {
            // the port is present, we don't care for its value
            *hLen = p2 - p;
        }
        else {
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
                return 0;
            else
                return -1;
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
        return 0;

    // otherwise iterate on headers and find the 'Host: '

    // get to the CR-LF
    p1 = memchr(p,13,pe-p);
    if (!p1 || p1 + 1 >= pe || p1[1] != 10)
        return -1;
    // and pass it
    p = p1+2;

    while (1)
    {
        // find the next CR-LF
        p2 = memchr(p,13,pe-p);
        if (!p2 || p2 + 1 >= pe || p2[1] != 10)
            break;
        // p2 - points to the next CR-LF

        if (p2 == p)
        // we are after the last header
            break;

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
        // port was found and it is before the next end-of-line
            *hLen = p1 - p;
        else
            *hLen = p2 - p;

#if 0  // for debugging
        int ccc = 0;
        if (ccc)
        {
            p = p2 + 2;
            continue;
        }
#endif

        break;
    }

    if (*hst)
        return 0;
    else
        return -1;
}

