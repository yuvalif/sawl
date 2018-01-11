#ifndef UPDATE_REDIS_H
#define UPDATE_REDIS_H

typedef struct _ThreadData ThreadData;

extern void disconnect_from_redis(ThreadData* td);
extern int connect_to_redis(ThreadData* td);
extern int set_to_redis(ThreadData* td, const char* ip, const char* name);
extern int del_from_redis(ThreadData* td, const char* ip);

#define REDIS_START_SCAN 0
#define REDIS_SCAN_END 0

extern int scan_redis(ThreadData* td, unsigned long* handle, char** ip, char** name, unsigned long* number_of_elements);

#endif
