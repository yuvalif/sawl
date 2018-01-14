#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hiredis/hiredis.h>
#include "trace.h"
#include "radius.h"
#include "update_redis.h"
#include "utils.h"

//static redisContext* redis_context = NULL;
static const char CHANNEL[32] = "RADIUS-IP-TO-USER-ID-CHANNEL";

void disconnect_from_redis(ThreadData* td)
{
    if (td->redis_context != NULL)
    {
        /* Disconnects and frees the context */
        LOG(LOG_INFO, "REDIS connection closing...\n");
        redisFree(td->redis_context);
        td->redis_context = NULL;
    }
    else
        LOG(LOG_DBG, "REDIS connection already closed\n");
}

int connect_to_redis(ThreadData* td)
{
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    disconnect_from_redis(td);
    td->redis_context = redisConnectWithTimeout(cfg.redis_host, cfg.redis_port, timeout);
    if (td->redis_context == NULL || td->redis_context->err)
    {
        if (td->redis_context)
        {
                LOG(LOG_ERR, "REDIS connection error to %s:%d is: %s\n", cfg.redis_host, cfg.redis_port, td->redis_context->errstr);
                disconnect_from_redis(td);
        }
        else
        {
            LOG(LOG_ERR, "REDIS connection error: can't allocate redis context\n");
        }
        return REDIS_ERR;
    }

    LOG(LOG_INFO, "REDIS connection to: %s:%d established\n", cfg.redis_host, cfg.redis_port);
    return REDIS_OK;
}

/*TODO write in asynch mode for better performance*/

int set_to_redis(ThreadData* td, const char* ip, const char* name)
{
    redisReply *reply = NULL;

    if (!td->is_first_thread)
        return 0;

    if (td->redis_context == NULL)
    {
        LOG(LOG_DBG, "REDIS not connected. Cannot PUBLISH %s ADD,%s,%s\n", CHANNEL, ip, name);
        return REDIS_ERR;
    }

    reply = redisCommand(td->redis_context, "PUBLISH %s ADD,%s,%s",  CHANNEL, ip, name);
    /* TODO check reply */
    LOG(LOG_DBG, "REDIS PUBLISH %s ADD,%s,%s\n",  CHANNEL, ip, name);
    freeReplyObject(reply);
    return REDIS_OK;
}

int del_from_redis(ThreadData* td, const char* ip)
{
    redisReply *reply = NULL;

    if (!td->is_first_thread)
        return 0;

    if (td->redis_context == NULL)
    {
        LOG(LOG_DBG, "REDIS not connected. Cannot PUBLISH %s REMOVE,%s\n",  CHANNEL, ip);
        return REDIS_ERR;
    }

    reply = redisCommand(td->redis_context, "PUBLISH %s REMOVE,%s",  CHANNEL, ip);
    /* TODO check reply */
    LOG(LOG_DBG, "REDIS PUBLISH %s REMOVE,%s\n",  CHANNEL, ip);
    freeReplyObject(reply);
    return REDIS_OK;
}

#define MIN(a,b) (a) < (b) ? (a) : (b)
#define MAX(a,b) (a) > (b) ? (a) : (b)

int get_from_redis(ThreadData* td, const char* ip, char** name)
{
    redisReply *reply = NULL;

    if (td->redis_context == NULL)
    {
        LOG(LOG_DBG, "REDIS not connected. Cannot GET %s\n", ip);
        return REDIS_ERR;
    }

    reply = redisCommand(td->redis_context, "GET %s", ip);
    LOG(LOG_DBG, "REDIS GET %s\n", ip);
    if (reply == NULL)
    {
        LOG(LOG_DBG, "No key found for REDIS GET %s\n", ip);
        return REDIS_ERR;
    }
    if (reply->type == REDIS_REPLY_STRING)
    {
        *name = (char*)malloc(MIN(SHA_DIGEST_LENGTH*2, reply->len)+1);
        memcpy(*name, reply->str, MIN(SHA_DIGEST_LENGTH*2, reply->len)+1);
    }
    else
    {
        LOG(LOG_DBG, "Invalid reply format for REDIS GET %s\n", ip);
        return REDIS_ERR;
    }
    freeReplyObject(reply);
    return REDIS_OK;
}

int scan_redis(ThreadData* td, unsigned long* handle, char** ip, char** name, unsigned long* number_of_elements)
{
    redisReply *reply = NULL;
    unsigned long redis_i = 0;

    *number_of_elements = 0;

    if (td->redis_context == NULL)
    {
        LOG(LOG_DBG, "REDIS not connected. Cannot run full scan on handle%lu\n", *handle);
        return REDIS_ERR;
    }
    reply = redisCommand(td->redis_context, "SCAN %u", *handle);
    if (reply == NULL)
    {
        LOG(LOG_DBG, "Failed to run full scan on handle %lu\n", *handle);
        return REDIS_ERR;
    }

    if (reply->type == REDIS_REPLY_ARRAY)
    {
        if (reply->elements == 2 &&
                reply->element[0]->type == REDIS_REPLY_STRING &&
                reply->element[1]->type == REDIS_REPLY_ARRAY)
        {
            unsigned long db_i = 0;
            *handle = strtoul(reply->element[0]->str, NULL, 0);
            *number_of_elements = reply->element[1]->elements;
            /*TODO check that number of elements dont exceed max*/
            for (; redis_i < reply->element[1]->elements; redis_i++)
            {
                if (reply->element[1]->element[redis_i]->type == REDIS_REPLY_STRING)
                {
                    char* tmp_name;
                    /* get the name for that IP*/
                    if (get_from_redis(td,reply->element[1]->element[redis_i]->str, &tmp_name) == REDIS_OK)
                    {
                        /* copy IP and convert commas to dots*/
                        char* c = reply->element[1]->element[redis_i]->str;
                        int j = 0;
                        const int str_len = MIN(reply->element[1]->element[redis_i]->len,16);
                        ip[db_i] = (char*)malloc(16*sizeof(char));
                        while (j < str_len)
                        {
                            ip[db_i][j] = (*c == ',') ? '.' : *c;
                            j++;
                            c++;
                        }
                        ip[db_i][str_len] = '\0';
                        name[db_i] = tmp_name;
                        db_i++;
                    }
                    else
                    {
                        /* skip the missing value and continue*/
                        LOG(LOG_DBG, "Name not found for IP %s when running full scan for handle %lu\n", ip[db_i], *handle);
                    }
                }
                else
                {
                    LOG(LOG_DBG, "Invalid reply format when running full scan for handle %lu\n", *handle);
                    /* skip the bad value and continue*/
                }
            }
        }
        else
        {
            LOG(LOG_DBG, "Invalid reply format when running full scan for handle %lu\n", *handle);
            return REDIS_ERR;
        }
    }
    else
    {
        LOG(LOG_DBG, "Invalid reply format when running full scan for handle %lu\n", *handle);
        return REDIS_ERR;
    }

    *number_of_elements = redis_i;
    freeReplyObject(reply);
    return REDIS_OK;
}


//typedef struct redisReply {
//    int type; /* REDIS_REPLY_* */
//    long long integer; /* The integer when type is REDIS_REPLY_INTEGER */
//    size_t len; /* Length of string */
//    char *str; /* Used for both REDIS_REPLY_ERROR and REDIS_REPLY_STRING */
//    size_t elements; /* number of elements, for REDIS_REPLY_ARRAY */
//    struct redisReply **element; /* elements vector for REDIS_REPLY_ARRAY */
//} redisReply;




