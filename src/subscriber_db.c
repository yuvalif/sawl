#include <hiredis/hiredis.h>
#include <openssl/sha.h>

#include "uthash.h"
#include "trace.h"
#include "stats.h"
#include "update_redis.h"
#include "update_csv.h"
#include "subscriber_db.h"
#include "utils.h"

//static struct subscriber_stats* g_stats;
//static int synch_with_redis = 0;
//static struct ip_to_name_entry* ip_to_name_table  = NULL;


static void set_to_db_internal(ThreadData* td, const char* ip, const char* name)
{
    struct ip_to_name_entry* s = NULL;

    HASH_FIND_STR(td->ip_to_name_table, ip, s);
    if (s)
    {

        if (memcmp(s->_name, name, SHA_DIGEST_LENGTH*2) != 0)
        {
            LOG(LOG_WARN, "Subscriber's IP %s already in DB with different name. Updating name from: %s to %s\n",
                ip, s->_name, name);

            if (td->is_first_thread)
            {
                subscr_stats.subscriber_implicit_logout_start++;
                subscr_stats.subscriber_implicit_logout_period++;

            }
            strncpy(s->_name, name, SHA_DIGEST_LENGTH*2+1);
        }
        else
        {
            LOG(LOG_DBG, "Subscriber's IP %s already in DB with same name\n", ip);
            if (td->is_first_thread)
            {
                subscr_stats.update_no_op_start++;
                subscr_stats.update_no_op_period++;
            }
        }
    }
    else
    {
        if (td->is_first_thread)
        {
            subscr_stats.subscriber_added_start++;
            subscr_stats.subscriber_added_period++;
            subscr_stats.hash_length++;
        }
        LOG(LOG_DBG, "New Subscriber with IP %s and name %s added to DB\n", ip, name);
        s = (struct ip_to_name_entry*)malloc(sizeof(struct ip_to_name_entry));
        strncpy(s->_ip, ip, 16);
        strncpy(s->_name, name, SHA_DIGEST_LENGTH*2+1);
        HASH_ADD_STR(td->ip_to_name_table, _ip, s);
    }
}

void init_db(ThreadData* td)
{
    LOG(LOG_INFO, "Initializing subscriber DB\n");
    init_csv(td);
    if (cfg.redis_host == NULL || strlen(cfg.redis_host) == 0)
    {
        LOG(LOG_INFO, "REDIS updates are disabled\n");
        return;
    }

    /*TODO: load db after failure*/
    if (connect_to_redis(td) == REDIS_OK)
    {
        unsigned long handle = REDIS_START_SCAN;
        char* ips[100];
        char* names[100];
        unsigned long number_of_elements;
        td->synch_with_redis = 1;
        if (scan_redis(td, &handle, ips, names, &number_of_elements) != REDIS_ERR)
        {
            LOG(LOG_DBG, "Synching %lu elements from REDIS\n", number_of_elements);
            unsigned long i;
            for (i = 0; i < number_of_elements; i++)
            {
                if (td->is_first_thread)
                    subscr_stats.successful_syncs++;
                LOG(LOG_DBG, "Synching element (%s %s) from REDIS\n", ips[i], names[i]);
                set_to_db_internal(td, ips[i], names[i]);
                free(ips[i]);
                free(names[i]);
            }
            while (handle != REDIS_SCAN_END)
            {
                if (scan_redis(td, &handle, ips, names, &number_of_elements) != REDIS_ERR)
                {
                    LOG(LOG_DBG, "Synching %lu elements from REDIS\n", number_of_elements);
                    for (i = 0; i < number_of_elements; i++)
                    {
                        if (td->is_first_thread)
                            subscr_stats.successful_syncs++;
                        LOG(LOG_DBG, "Synching element (%s %s) from REDIS\n", ips[i], names[i]);
                        set_to_db_internal(td, ips[i], names[i]);
                        free(ips[i]);
                        free(names[i]);
                    }
                }
                else
                {
                    LOG(LOG_ERR, "Loading initial data from REDIS failed\n");
                    break;
                }
            }
        }
        else
        {
            LOG(LOG_ERR, "Loading initial data from REDIS failed\n");
        }

        if (!td->is_first_thread)
            // if this is not redis writing thread, we do not need to keep the DB connection
            // once scan has been done
            disconnect_from_redis(td);
    }
    else
    {
        LOG(LOG_ERR, "Connection to REDIS failed\n");
        /*TODO: retry connections*/
    }
}

void close_db(ThreadData* td)
{
    if (td->synch_with_redis)
    {
        disconnect_from_redis(td);
        td->synch_with_redis = 0;
    }

    if (td->ip_to_name_table)
    {
        struct ip_to_name_entry* s = NULL;
        struct ip_to_name_entry* tmp = NULL;
        int count = 0;

        /* free the hash table contents */
        HASH_ITER(hh, td->ip_to_name_table, s, tmp)
        {
            ++count;
            HASH_DEL(td->ip_to_name_table, s);
            free(s);
        }
        LOG(LOG_INFO, "Closing subscriber DB...%d entries cleared\n", count);
        td->ip_to_name_table  = NULL;
    }
    else
    {
        LOG(LOG_WARN, "Subscriber DB already closed\n");
    }
    close_csv(td);
}

void dump_entry(struct ip_to_name_entry* s)
{
    printf("IP: %s Name: %s\n", s->_ip, s->_name);
}

void dump_db(ThreadData* td)
{
    if (td->ip_to_name_table)
    {
        struct ip_to_name_entry* s = NULL;
        struct ip_to_name_entry* tmp = NULL;

        /* free the hash table contents */
        HASH_ITER(hh, td->ip_to_name_table, s, tmp)
        {
            dump_entry(s);
        }
    }
    else
    {
        /* DB closed */
        LOG(LOG_ERR, "Subscriber DB closed. Cannot dump\n");
    }
}

void set_to_db(ThreadData* td, const char* ip, const char* name)
{
    if (td->synch_with_redis)
    {
        set_to_redis(td, ip, name);
    }

    set_to_db_internal(td, ip, name);
}

void set_location_to_db(ThreadData* td, const char* ip, const char* name, int location)
{
    /* TODO: aggregate into DB and log every hour or on logout */
    write_location_csv(td, name, location);
}

void set_host_to_db(ThreadData* td, const char* ip, const char* host)
{
    /* TODO: aggregate into DB and log every hour or on logout */
    struct ip_to_name_entry* s = NULL;
    HASH_FIND_STR(td->ip_to_name_table, ip, s);
    if (s)
    {
        /*TODO must aggregate and not write directly to file*/
        write_host_csv(td, s->_name, host);
    }
    else
    {
        if (td->is_first_thread)
        {
            subscr_stats.http_subscriber_not_found_start++;
            subscr_stats.http_subscriber_not_found_period++;
        }
        LOG(LOG_WARN, "Could not find subscriber name matching IP %s when updating HTTP host: %s\n",
            ip, host);
    }
}

void set_url_to_db(ThreadData* td, const char* ip, const char* url, const char* host)
{
    struct ip_to_name_entry* s = NULL;
    HASH_FIND_STR(td->ip_to_name_table, ip, s);
    if (s)
    {
        write_url_csv(td, s->_name, url, host);
    }
    else
    {
        if (td->is_first_thread)
        {
            subscr_stats.http_subscriber_not_found_start++;
            subscr_stats.http_subscriber_not_found_period++;
        }
        LOG(LOG_WARN, "Could not find subscriber name matching IP %s when updating HTTP URL: %s%s\n",
            ip, host, url);
    }
}

void del_from_db(ThreadData* td, const char* ip)
{

    if (td->synch_with_redis)
    {
        del_from_redis(td, ip);
    }

    if (td->ip_to_name_table)
    {
        struct ip_to_name_entry* s = NULL;
        HASH_FIND_STR(td->ip_to_name_table, ip, s);
        if (s)
        {
            if (td->is_first_thread)
            {
                subscr_stats.subscriber_deleted_start++;
                subscr_stats.subscriber_deleted_period++;
                subscr_stats.hash_length--;
            }
            LOG(LOG_DBG, "Subscriber with IP %s and name %s deleted DB\n", ip, s->_name);
            HASH_DEL(td->ip_to_name_table, s);
            free(s);
        }
        else
        {
            if (td->is_first_thread)
            {
                subscr_stats.subscriber_deleted_failed_start++;
                subscr_stats.subscriber_deleted_failed_period++;
            }
            /* subscriber logout but never logged in*/
            LOG(LOG_WARN, "Subscriber with IP %s not in DB. Cannot delete\n", ip);
        }
    }
    else
    {
        /* DB closed*/
        LOG(LOG_ERR, "Subscriber DB closed. Cannot delete\n");
    }
}

