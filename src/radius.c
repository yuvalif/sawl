#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "trace.h"
#include "radius.h"
#include "utils.h"

void print_radius_info(struct radius_info* info)
{
    printf("Subscriber ID: %s\n", info->_name);
    printf("Subscriber IP: %s\n", info->_ip);
    if (info->_location_update)
    {
        printf("Cell ID: %d\n", info->_cell_id);
    }
}

void append_radius_info(struct radius_attr *ra, struct radius_info* info)
{
    const unsigned int ACC_STATUS_TYPE_ID = 40;
    const unsigned int CALLING_STATION_ID = 31;
    const unsigned int VSA_ID = 26;
    const unsigned int TGPP_VENDOR_ID = 10415;
    const unsigned int TGPP_USER_LOCATION_INFO_ID = 22;
    const unsigned int FRAMED_IP_ADDRESS_ID = 8;

    assert(ra != NULL);
    assert(info != NULL);

    /*look for Acc-Status-Type attribute*/
    if (ra->type == ACC_STATUS_TYPE_ID)
    {
        unsigned int val;
        memcpy(&val, &(ra->value[0]), sizeof(val));
        val = ntohl(val);
        /*handle START and INTERIM only*/
        if (val == 1 || val == 3)
        {
            info->_login_or_update = 1;
        }
        else if (val == 2)
        {
            info->_logout = 1;
        }
        else
        {
            /* other message type */
        }
        LOG(LOG_DBG, "Acc-Status-Type AVP with value %s (%d)\n",
                (val == 1) ? "START" : ((val == 2) ? "STOP" : ((val == 3) ? "INTERIM" : "OTHER")),
                val);
    }
    /*look for Calling-Station-Id attribute*/
    else if (ra->type == CALLING_STATION_ID)
    {
        unsigned int i;
        char str[3];
        unsigned char hashed_text[SHA_DIGEST_LENGTH];

        info->_name[0] = '\0';
        SHA1(&ra->value[0], ra->len - 2, hashed_text);
        for(i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            /*TODO store in binary format*/
            sprintf(str, "%02x", hashed_text[i]);
            strcat(info->_name, str);
        }
        info->_has_name = 1;
        LOG(LOG_DBG, "Calling-Station-Id AVP with value obfuscated value: %s\n",
                info->_name);
    }
    /*look for Framed-IP-Address attribute*/
    else if (ra->type == FRAMED_IP_ADDRESS_ID)
    {
        struct in_addr a;

        memcpy(&a, &(ra->value[0]), sizeof(a));
        /*TODO store in binary format*/
        sprintf(info->_ip, "%s", inet_ntoa(a));
        info->_has_ip = 1;
    }
    /*look for 3GPP-User-Location-Info VSA*/
    else if (ra->type == VSA_ID)
    {
        unsigned int vendor;
        struct radius_attr *vsa;

        memcpy(&vendor, &(ra->value[0]), sizeof(vendor));
        vendor = ntohl(vendor);
        if (vendor == TGPP_VENDOR_ID)
        {
            vsa = (struct radius_attr *)&(ra->value[4]);
            if (vsa->type == TGPP_USER_LOCATION_INFO_ID)
            {
                unsigned short cell_id;
                unsigned int lte_cell_id;
                switch (vsa->value[0])
                {
                    case 0:
                        memcpy(&cell_id, &vsa->value[6], 2);
                        info->_cell_id = ntohs(cell_id);
                        info->_location_update = 1;
                        LOG(LOG_DBG, "3GPP-User-Location-Info VSA of type GCI with cell ID: %d\n", info->_cell_id);
                        break;
                    case 129:
                        LOG(LOG_DBG, "3GPP-User-Location-Info VSA of type EGCI not needed for info\n");
                        /*memcpy(&lte_cell_id, HI_NIBBLE(vsa->value[3]), 1);
                        memcpy(&lte_cell_id + 1, &ra->value[4], 3);
                        info->_cell_id = ntohl(lte_cell_id);
                        info->_location_update = 1;*/
                        break;
                    case 130:
                        LOG(LOG_DBG, "3GPP-User-Location-Info VSA of type TAI/EGCI not needed for info\n");
                        /*memcpy(&lte_cell_id, HI_NIBBLE(vsa->value[4]), 1);
                        memcpy(&lte_cell_id + 1, &ra->value[5], 3);
                        info->_cell_id = ntohl(lte_cell_id);
                        info->_location_update = 1;*/
                        break;
                    default:
                        LOG(LOG_DBG, "3GPP-User-Location-Info VSA of type %d not needed for info\n", vsa->value[0]);
                        break;
                }
            }
            else
            {
                LOG(LOG_DBG, "VSA of type %d not needed for info\n", vsa->type);
            }
        }
        else
        {
                LOG(LOG_DBG, "VSA with vendor id %d not needed for info\n", vsa->type);
        }
    }
    else
    {
        LOG(LOG_DBG, "RADIUS AVP type %d not needed for info\n", ra->type);
    }
    return;
}

