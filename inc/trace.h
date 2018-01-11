#ifndef _TRACE_H
#define _TRACE_H

#ifndef LOGS
#define NOLOGS
#endif

#define LOG_FATAL    (1)
#define LOG_ERR      (2)
#define LOG_WARN     (3)
#define LOG_INFO     (4)
#define LOG_DBG      (5)

#ifdef NOLOGS

#define LOG(level, ...) (void)level;

#else

#include <stdio.h>
#include <time.h>
#include <string.h>


#define LOG(level, ...) do {  \
                            if (level <= cfg.debug_level) { \
                                time_t t; \
                                time(&t); \
                                char buff[26]; \
                                ctime_r(&t, buff); \
                                buff[strlen(buff) - 1] = '\0'; \
                                fprintf(stdout, "%s %s ", buff, \
                                        level == LOG_FATAL ? "LOG_FATAL" : \
                                        level == LOG_ERR ? "LOG_ERR" : \
                                        level == LOG_WARN ? "LOG_WARN" : \
                                        level == LOG_INFO ? "LOG_INFO" : \
                                        level == LOG_DBG ? "LOG_DBG" : "LOG_NONE"), \
                                fprintf(stdout, __VA_ARGS__); \
                                fflush(stdout); \
                            } \
                        } while (0)


#endif

#endif

