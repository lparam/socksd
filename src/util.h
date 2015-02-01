#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>


#define TIME_FORMAT "%F %T"

#define LOGI(format, ...)                                                \
    do {                                                                 \
        time_t now = time(NULL);                                         \
        char timestr[20];                                                \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));             \
        fprintf(stderr, "\e[01;32m %s INFO: \e[0m" format "\n", timestr, \
                ## __VA_ARGS__);                                         \
    }                                                                    \
    while (0)

#define LOGE(format, ...)                                                 \
    do {                                                                  \
        time_t now = time(NULL);                                          \
        char timestr[20];                                                 \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));              \
        fprintf(stderr, "\e[01;35m %s ERROR: \e[0m" format "\n", timestr, \
                ## __VA_ARGS__);                                          \
    }                                                                     \
    while (0)

int resolve_addr(const char *buf, struct sockaddr *addr);
int ip_name(const struct sockaddr *ip, char *name, size_t size);
void dump_hex(const void *data, uint32_t len, char *title);
#endif // for #ifndef _UTIL_H
