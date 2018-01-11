/* packet.c */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "packet.h"

void print_as_ethernet_header(char* ptr)
{
    ethhdr* eth_hdr = (ethhdr*)ptr;
    static char buff[18];

    printf("\n========================================\n");
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet (IP) Header\n");
        printf("Source MAC Address: %s\n", ether_ntoa_r((struct ether_addr*)eth_hdr->ether_shost, buff));
        printf("Destination MAC Address: %s\n", ether_ntoa_r((struct ether_addr*)eth_hdr->ether_dhost, buff));
        printf("Type: 0x%x\n", ntohs(eth_hdr->ether_type));
    }
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN)
    {
        vlhdr* vl_hdr = (vlhdr*)ptr;
        printf("Ethernet (VLAN) Header\n");
        printf("Source MAC Address: %s\n", ether_ntoa_r((struct ether_addr*)vl_hdr->ether_shost, buff));
        printf("Destination MAC Address: %s\n", ether_ntoa_r((struct ether_addr*)vl_hdr->ether_dhost, buff));
        printf("ID: %d\n", VLAN_ID(vl_hdr));
        printf("Encapsulated Type: 0x%x\n", ntohs(vl_hdr->ether_type));
    }
    else
    {
        printf("Ethernet Header\n");
        printf("Source MAC Address: %s\n", ether_ntoa_r((struct ether_addr*)eth_hdr->ether_shost, buff));
        printf("Destination MAC Address: %s\n", ether_ntoa_r((struct ether_addr*)eth_hdr->ether_dhost, buff));
        printf("Type: 0x%x\n", ntohs(eth_hdr->ether_type));
    }
    printf("========================================\n\n");

}

void print_as_ip_header(char* ptr)
{
    /*TODO*/
}

void print_as_tcp_header(char* ptr)
{
    /*TODO*/
}

int ssl_find_host_name(const char* _p, int len, char* host, int hostLen, int* isHelloMessage)
{
    unsigned char *p = (unsigned char*) _p, *pe = p + len;
    int n, type;

#define SSL3_RT_HANDSHAKE               22
#define SSL3_MT_CLIENT_HELLO             1
#define SSL3_MT_SERVER_HELLO             2


#define TEST_OUT_OF_PACKET()  if (p >= pe) {return -1;}

    *isHelloMessage = 0;

    // following code is based on RFC 5246

    // we need only handshake
    if (*p++ != SSL3_RT_HANDSHAKE)
        return -1;

    TEST_OUT_OF_PACKET();

    // SSL version
    if (*p < 3)
    {
        // SNI is supported from SSL 3.0 (SSL 3.1 is TLS 1.0)
        return -1;
    }
    p+=2;
    TEST_OUT_OF_PACKET();

    // length
    n = (*p++<<8) + (*p++);
    TEST_OUT_OF_PACKET();

    if (p + n < pe)
        // possibly fix the last byte of the header
        // possibly,  because it is quite possible this packet does not hold the full handshake message
        pe = p + n;

    if (*p != SSL3_MT_CLIENT_HELLO && *p != SSL3_MT_SERVER_HELLO)
        return -1;

    p++;

    *isHelloMessage = 1;

    n = (*p++<<16) + (*p++<<8) + (*p++);

    if (p + n < pe)
        pe = p + n;

    // skip protocol version
    p += 2;
    // skip random
    p += 32;
    TEST_OUT_OF_PACKET();

    // session ID
    n = *p++;
    if (n >= 32)
        // test length is legal
        return -1;
    p += n;
    TEST_OUT_OF_PACKET();

    // cypher suites
    // get the length
    n = (*p++<<8) + (*p++);
    if (n < 0 || n > 0xFFFF-2)
        // test length is legal
        return -1;
    // skip the cypher suites
    p += n;
    TEST_OUT_OF_PACKET();

    // compression methods
    // get the length
    n = *p++;
    if (n < 0 || n > 255)
        // test length is legal
        return -1;
    // skip the compression methods
    p += n;
    TEST_OUT_OF_PACKET();

    // extension length
    n = (*p++<<8) + (*p++);
    if (p + n < pe)
        pe = p + n;

    // loop over the extensions
    while (p < pe)
    {

        type = (*p++<<8) + (*p++);
        n = (*p++<<8) + (*p++);
        if (type != 0)
        {
            // server-name has type 0
            p += n;
            continue;
        }

        // we are on server-name extension
        // from here RFC 6066

        // get the server name list length
        n = (*p++<<8) + (*p++);

        // fix the last byte to look for
        if (p + n < pe)
            pe = p + n;

        while (p < pe)
        {
            int nameType;
            char *name;
            int nameLen;

            nameType = *p++;
            nameLen = (*p++<<8) + (*p++);
            name = p;

            if (nameType != 0) // we need the HostName which is 0
                p += nameLen;

            // bingo: we are at host name
            if (p + nameLen > pe)
            {
                //LOG(LOG_WARN, "SSL server name extension is truncated on the packet end\n");
                return -1;
            }

            if (nameLen > hostLen-1)
            {
                //LOG(LOG_WARN, "SSL server name is bigger (%d) than provided buffer(%d)\n",nameLen,hostLen);
                return -1;
            }

            if (nameLen == 0)
            {
                // namelen may generally be empty
                return -1;
            }

            memcpy(host,name,nameLen);

            host[nameLen] = 0;
            //LOG(LOG_INFO, "SSL server name extension found: %s\n",host);
            return 0;
        }
    }

    return -1;
}

