#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "uv.h"
#include "udns.h"
#include "util.h"
#include "logger.h"
#include "resolver.h"


struct dns_query {
    dns_host_callback callback;
    void *data;
    uint16_t port;
    struct dns_query *queries[2];
    struct sockaddr **responses;
    size_t response_count;
    struct resolver_context *context;
};

struct resolver_context {
    struct dns_ctx *dns;
    uv_timer_t timer;
    uv_poll_t watcher;
};

extern int verbose;
static int mode = MODE_IPV4;

static struct sockaddr *
choose_address(struct dns_query *query, sa_family_t sa) {
    for (int i = 0; i < query->response_count; i++) {
        if (query->responses[i]->sa_family == sa) {
            return query->responses[i];
        }
    }

    if (query->response_count >= 1) {
        return query->responses[0];
    }

    return NULL;
}

static int
check_query(struct dns_query *query) {
    int ret = 1;
    int qc = sizeof(query->queries) / sizeof(query->queries[0]);

    for (int i = 0; i < qc; i++) {
        ret = ret && query->queries[i] == NULL;
    }

    return ret;
}

static void
handle_result(struct dns_query *query) {
    struct sockaddr *addr = NULL;

    if (mode == MODE_IPV4_FIRST) {
        addr = choose_address(query, AF_INET);
    } else if (mode == MODE_IPV6_FIRST) {
        addr = choose_address(query, AF_INET6);
    } else {
        addr = choose_address(query, AF_UNSPEC);
    }

    query->callback(addr, query->data);

    for (int i = 0; i < query->response_count; i++) {
        free(query->responses[i]);
    }

    free(query->responses);
    free(query);
}

static void
dns_query_a4_cb(struct dns_ctx *dns, struct dns_rr_a4 *result, void *data) {
    struct dns_query *query = (struct dns_query *)data;

    if (result == NULL) {
        if (verbose) {
            logger_log(LOG_ERR, "IPv4 resolver: %s", dns_strerror(dns_status(dns)));
        }
    } else if (result->dnsa4_nrr > 0) {
        query->responses = realloc(query->responses, (query->response_count + result->dnsa4_nrr) * sizeof(struct sockaddr *));
        query->response_count = result->dnsa4_nrr;
        for (int i = 0; i < result->dnsa4_nrr; i++) {
            struct sockaddr_in *sa = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
            sa->sin_family = AF_INET;
            sa->sin_addr = result->dnsa4_addr[i];
            sa->sin_port = query->port;
            query->responses[i] = (struct sockaddr *)sa;
        }
    }

    free(result);
    query->queries[0] = NULL;

    if (check_query(query)) {
        handle_result(query);
    }
}

static void
dns_query_a6_cb(struct dns_ctx *dns, struct dns_rr_a6 *result, void *data) {
    struct dns_query *query = (struct dns_query *)data;

    if (result == NULL) {
        if (verbose) {
            logger_log(LOG_ERR, "IPv6 resolver: %s", dns_strerror(dns_status(dns)));
        }
    } else if (result->dnsa6_nrr > 0) {
        query->responses = realloc(query->responses, (query->response_count + result->dnsa6_nrr) * sizeof(struct sockaddr *));
        query->response_count = result->dnsa6_nrr;
        for (int i = 0; i < result->dnsa6_nrr; i++) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6));
            sa->sin6_family = AF_INET6;
            sa->sin6_addr = result->dnsa6_addr[i];
            sa->sin6_port = query->port;
            query->responses[i] = (struct sockaddr *)sa;
        }
    }

    free(result);
    query->queries[1] = NULL;

    if (check_query(query)) {
        handle_result(query);
    }
}

static void
timer_expire(uv_timer_t *handle) {
    struct dns_ctx *dns = (struct dns_ctx *)handle->data;
    uint64_t now = uv_now(handle->loop);
    dns_timeouts(dns, 30, now);
}

static void
dns_timer_cb(struct dns_ctx *dns, int timeout, void *data) {
    uv_timer_t *timer = data;
    if (dns != NULL && timeout >= 0) {
        uv_timer_start(timer, timer_expire, timeout * 1000, 0);
    }
}

static void
udns_poll_cb(uv_poll_t *watcher, int status, int events) {
    if (!status) {
        struct dns_ctx *dns = (struct dns_ctx *)watcher->data;
        uint64_t now = uv_now(watcher->loop);
        dns_ioevent(dns, now);
    } else {
        logger_log(LOG_ERR, "poll error: %s", uv_strerror(status));
    }
}

void
resolver_prepare(int nameserver_num) {
    if (nameserver_num > 0) {
        dns_reset(&dns_defctx);
    } else {
        dns_init(&dns_defctx, 0);
    }
}

struct resolver_context *
resolver_init(uv_loop_t *loop, int m, char **nameservers, int nameserver_num) {
    struct dns_ctx *dns;
    struct resolver_context *ctx;

    mode = m;
    dns = dns_new(&dns_defctx);

    if (nameserver_num > 0) {
        dns_reset(dns);
        dns_set_opt(dns, DNS_OPT_TIMEOUT, 2);
        for (int i = 0; i < nameserver_num; i++) {
            char *server = nameservers[i];
            dns_add_serv(dns, server);
        }
    } else {
        dns_init(dns, 0);
    }

    int sockfd = dns_open(dns);
    assert(sockfd >= 0 && "Failed to open DNS resolver socket");

    ctx = malloc(sizeof(*ctx));
    ctx->dns = dns;

    uv_poll_init_socket(loop, &ctx->watcher, sockfd);

    ctx->watcher.data = dns;
    uv_poll_start(&ctx->watcher, UV_READABLE, udns_poll_cb);

    ctx->timer.data = dns;
    uv_timer_init(loop, &ctx->timer);

    dns_set_tmcbck(dns, dns_timer_cb, &ctx->timer);

    return ctx;
}

struct dns_query *
resolver_query(struct resolver_context *ctx, const char *host, uint16_t port, dns_host_callback cb, void *data) {
    struct dns_ctx *dns = ctx->dns;

    struct dns_query *query = malloc(sizeof(struct dns_query));
    query->callback = cb;
    query->port = port;
    query->data = data;
    memset(query->queries, 0, sizeof(query->queries));
    query->response_count = 0;
    query->responses = NULL;
    query->context = ctx;

    if (mode != MODE_IPV6) {
        query->queries[0] = dns_submit_a4(dns, host, 0, dns_query_a4_cb, query);
        if (query->queries[0] == NULL) {
            logger_log(LOG_ERR, "Failed to submit DNS query: %s", dns_strerror(dns_status(dns)));
        }
    }

    if (mode != MODE_IPV4) {
        query->queries[1] = dns_submit_a6(dns, host, 0, dns_query_a6_cb, query);
        if (query->queries[1] == NULL) {
            logger_log(LOG_ERR, "Failed to submit DNS query: %s", dns_strerror(dns_status(dns)));
        }
    }

    if (check_query(query)) {
        free(query);
        query = NULL;
    }

    return query;
}

void
resolver_shutdown(struct resolver_context *ctx) {
    uv_poll_stop(&ctx->watcher);
    uv_close((uv_handle_t *)&ctx->timer, NULL);
}

void
resolver_destroy(struct resolver_context *ctx) {
    dns_free(ctx->dns);
    free(ctx);
}

void
resolver_cancel(struct dns_query *query) {
    struct dns_ctx *dns = query->context->dns;
    int qc = sizeof(query->queries) / sizeof(query->queries[0]);

    for (int i = 0; i < qc; i++) {
        if (query->queries[i] != NULL) {
            dns_cancel(dns, query->queries[i]);
            free(query->queries[i]);
            query->queries[i] = NULL;
        }
    }

    free(query);
}
