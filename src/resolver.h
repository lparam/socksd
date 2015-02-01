#ifndef _RESOLVER_H
#define _RESOLVER_H

#include <stdint.h>
#include <sys/socket.h>
#include <uv.h>


struct dns_query;
struct resolver_context;

enum resolver_mode {
    MODE_IPV4,
    MODE_IPV6,
    MODE_IPV4_FIRST,
    MODE_IPV6_FIRST,
};

typedef void (*dns_host_callback)(struct sockaddr *addr, void *data);

void resolver_prepare(int nameserver_num);
struct resolver_context * resolver_init(uv_loop_t *loop, int mode, char **nameservers, int nameserver_num);
struct dns_query *resolver_query(struct resolver_context *ctx, const char *hostname, dns_host_callback cb, void *data);
void resolver_cancel(struct dns_query *);
void resolver_shutdown(struct resolver_context *rctx);
void resolver_destroy(struct resolver_context *ctx);

#endif // for #ifndef _RESOLVER_H
