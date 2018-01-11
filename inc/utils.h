#ifndef __UTILS_H__
#define __UTILST_H__

#include <semaphore.h>
#include <stdio.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include <openssl/sha.h>

#include "stats.h"
#include "uthash.h"

#define DEFAULT_URL_LEN             0
#define DEFAULT_PRINT               25
#define DEFAULT_PERIOD              3600
#define DEFAULT_REDIS_PORT          6379
#define DEFAULT_SNAP_LEN            1600
#define DEFAULT_THREADS_NUM         10
#define DEFAULT_PACKS_PER_BUCKET    10000

#define DEFAULT_UDP_PACKETS         1000

typedef struct {
    int             ssl_sni_enabled;
    int             only_ip_processing;
    unsigned int    url_len;
    int             mode;
    char            interface[256];
    char            tracefile[256];
    char            redis_host[128];
    unsigned long   period;
    unsigned short  redis_port;
    unsigned long   snap_len;
    unsigned long   period_between_prints;
    int             extended_statistics;

    unsigned long   packets_per_bucket;
    unsigned long   threads_num;

#ifndef NOLOGS
    unsigned long       debug_level;
#endif
} HttpSnifferCfg;


typedef struct {
    FILE*           location_file_p;
    FILE*           host_file_p;
    FILE*           url_file_p;
    time_t          location_creation_time;
    time_t          host_creation_time;
    time_t          url_creation_time;
} csv_data;

struct ip_to_name_entry {
    char            _ip[16];                       /*the IP address*/
    char            _name[SHA_DIGEST_LENGTH*2+1];  /* obfuscated subscriber name */
    UT_hash_handle   hh;                  /* makes this structure hashable */
};

typedef struct {
    char**                              packs;
    int*                                pack_lens;
    int                                 packs_saved;
    int                                 packs_sz;
} packets;

typedef struct _ThreadData {
    int                                 t_index;

    int                                 is_up;

    pthread_t                           thr;
    sem_t                               sema;
    int                                 is_processing;
    int                                 filled_up;

    packets                             p;
    int                                 packs_processed;

    packets                             udp_p;
    pthread_mutex_t                     udp_p_mtx;

    int                                 needToFinish;
    int                                 hasFinished;

    csv_data                            csv;

    redisContext*                       redis_context;
    int                                 is_first_thread;

    struct traffic_stats_per_thread     t_stats_short;
    int                                 statsUpdateCnt;
    struct traffic_stats_per_thread     t_stats_long;
    pthread_mutex_t                     stats_mtx;
    //struct traffic_stats_per_thread*    t_stats;

    struct ip_to_name_entry*            ip_to_name_table;
    int                                 synch_with_redis;

    //struct subscriber_stats             subscr_stats;
} ThreadData;

extern HttpSnifferCfg cfg;

extern struct subscriber_stats subscr_stats;



#endif