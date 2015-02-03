#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

int resolve_addr(const char *buf, struct sockaddr *addr);
int ip_name(const struct sockaddr *ip, char *name, size_t size);
void dump_hex(const void *data, uint32_t len, char *title);

#endif // for #ifndef _UTIL_H
