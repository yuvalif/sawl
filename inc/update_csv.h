#ifndef _UPDATE_CSV_H_
#define _UPDATE_CSV_H_

typedef struct _ThreadData ThreadData;

extern void init_csv(ThreadData* td);
extern void close_csv(ThreadData* td);
extern void write_location_csv(ThreadData* td, const char* name, int location);
extern void write_host_csv(ThreadData* td, const char* name, const char* host);
extern void write_url_csv(ThreadData* td, const char* name, const char* url, const char* host);

#endif

