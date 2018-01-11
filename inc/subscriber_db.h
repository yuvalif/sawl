#ifndef _SUBSCRIBER_DB_H_
#define _SUBSCRIBER_DB_H_

#include <stats.h>

typedef struct _ThreadData ThreadData;

extern void init_db(ThreadData* td);
extern void close_db(ThreadData* td);
extern void dump_db(ThreadData* td);
extern void set_to_db(ThreadData* td, const char* ip, const char* name);
extern void set_location_to_db(ThreadData* td, const char* ip, const char* name, int location);
extern void set_host_to_db(ThreadData* td, const char* ip, const char* host);
extern void set_url_to_db(ThreadData* td, const char* ip, const char* url, const char* host);
extern void del_from_db(ThreadData* td, const char* ip);

#endif

