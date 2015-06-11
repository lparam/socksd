#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))

int resolve_addr(const char *buf, struct sockaddr *addr);
int ip_name(const struct sockaddr *ip, char *name, size_t size);
void dump_hex(const void *data, uint32_t len, char *title);
int read_size(uint8_t *buffer);

#endif // for #ifndef _UTIL_H
