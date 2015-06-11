#include <stdlib.h>
#include <string.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "common.h"
#include "socks.h"
#include "cache.h"
#include "md5.h"
#include "resolver.h"


#define KEY_BYTES 32U
#define IPV4_HEADER_LEN 10 // 2 + 1 + 1 + 4 +2
#define IPV6_HEADER_LEN 22 // 2 + 1 + 1 + 16 +2

struct target_context {
    uv_udp_t                target_handle;
    uv_udp_t               *server_handle;
    struct sockaddr         client_addr;
    struct sockaddr         dest_addr;
    uint16_t                dest_port;
    uv_timer_t             *timer;
    struct dns_query       *addr_query;
    int                     header_len;
    uint8_t                *buf;
    ssize_t                 buflen;
    char                    key[KEY_BYTES + 1];
};

extern int verbose;
extern uint16_t idle_timeout;
static uv_mutex_t mutex;
static struct cache *cache;


static void
timer_expire(uv_timer_t *handle) {
    struct target_context *target = handle->data;
    uv_mutex_lock(&mutex);
    cache_remove(cache, target->key);
    uv_mutex_unlock(&mutex);
}

static void
timer_close_cb(uv_handle_t *handle) {
    free(handle);
}

static void
reset_timer(struct target_context *target) {
    target->timer->data = target;
    uv_timer_start(target->timer, timer_expire, idle_timeout * 1000, 0);
}


struct target_context *
new_target() {
    struct target_context *target = malloc(sizeof(*target));
    memset(target, 0, sizeof(*target));
    target->timer = malloc(sizeof(uv_timer_t));
    return target;
}

static void
target_close_cb(uv_handle_t *handle) {
    struct target_context *target = container_of(handle, struct target_context, target_handle);
    free(target);
}

static void
close_target(struct target_context *target) {
    uv_close((uv_handle_t *)target->timer, timer_close_cb);
    if (!uv_is_closing((uv_handle_t *)&target->target_handle)) {
        uv_close((uv_handle_t *)&target->target_handle, target_close_cb);
    } else {
        free(target);
    }
}

static int
parse_target_address(const uint8_t atyp, const char *addrbuf, struct sockaddr *addr, char *host) {
    int addrlen;
    uint16_t portlen = 2; // network byte order port number, 2 bytes
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } dest;

    memset(&dest, 0, sizeof(dest));

    if (atyp == S5_ATYP_IPV4) {
        size_t in_addr_len = sizeof(struct in_addr); // 4 bytes for IPv4 address
        dest.addr4.sin_family = AF_INET;
        memcpy(&dest.addr4.sin_addr, addrbuf, in_addr_len);
        memcpy(&dest.addr4.sin_port, addrbuf + in_addr_len, portlen);
        addrlen = 4 + portlen;

    } else if (atyp == S5_ATYP_HOST) {
        uint8_t namelen = *(uint8_t *)(addrbuf); // 1 byte of name length
        if (namelen > 0xFF) {
            return -1;
        }
        memcpy(&dest.addr4.sin_port, addrbuf + 1 + namelen, portlen);
        memcpy(host, addrbuf + 1, namelen);
        host[namelen] = '\0';
        addrlen = 1 + namelen + portlen;

    } else if (atyp == S5_ATYP_IPV6) {
        size_t in6_addr_len = sizeof(struct in6_addr); // 16 bytes for IPv6 address
        memcpy(&dest.addr6.sin6_addr, addrbuf, in6_addr_len);
        memcpy(&dest.addr6.sin6_port, addrbuf + in6_addr_len, portlen);
        addrlen = 16 + portlen;

    } else {
        return 0;
    }

    memcpy(addr, &dest.addr, sizeof(*addr));
    return addrlen;
}

static void
target_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct target_context *target = handle->data;
    buf->base = malloc(suggested_size) + target->header_len;
    memset(buf->base - target->header_len, 0, suggested_size);
    buf->len = suggested_size - target->header_len;
}

static void
client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void
client_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "forward to client failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)(req + 1);
    free(buf->base);
    free(req);
}

/*
 *
 * SOCKS5 UDP Response
 * +----+------+------+----------+----------+----------+
 * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 * +----+------+------+----------+----------+----------+
 * | 2  |  1   |  1   | Variable |    2     | Variable |
 * +----+------+------+----------+----------+----------+
 *
 */
static void
forward_to_client(struct target_context *target, uint8_t *data, ssize_t len) {
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = len;
    write_req->data = target;
    uv_udp_send(write_req, target->server_handle, buf, 1, &target->client_addr, client_send_cb);
}

static void
target_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    struct target_context *target = handle->data;
    if (nread > 0) {
        reset_timer(target);
        uint8_t *m = (uint8_t *)buf->base - target->header_len;
        ssize_t mlen = target->header_len + nread;

        memcpy(m, "\x0\x0\x0", 3); // RSV + FRAG
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
            m[3] = 1;
            memcpy(m + 4, &addr4->sin_addr, 4);
            memcpy(m + 4 + 4, &addr4->sin_port, 2);
        } else {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
            m[3] = 4;
            memcpy(m + 4, &addr6->sin6_addr, 16);
            memcpy(m + 4 + 16, &addr6->sin6_port, 2);
        }

        if (verbose) {
            char src[INET6_ADDRSTRLEN + 1] = {0};
            char dst[INET6_ADDRSTRLEN + 1] = {0};
            uint16_t src_port = 0, dst_port = 0;
            src_port = ip_name(addr, src, sizeof src);
            dst_port = ip_name(&target->client_addr, dst, sizeof dst);
            logger_log(LOG_INFO, "%s:%d -> %s:%d", src, src_port, dst, dst_port);
        }

        forward_to_client(target, m, mlen);

    } else {
        free(buf->base - target->header_len);
    }
}

static void
target_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        // TODO: close target
        logger_log(LOG_ERR, "forward to target failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)(req + 1);
    // free client recv buffer
    free(buf->base);
    free(req);
}

static void
forward_to_target(struct target_context *target, uint8_t *data, ssize_t len) {
    if (verbose) {
        char src[INET6_ADDRSTRLEN + 1] = {0};
        char dst[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t src_port = 0, dst_port = 0;
        src_port = ip_name(&target->client_addr, src, sizeof src);
        dst_port = ip_name(&target->dest_addr, dst, sizeof dst);
        logger_log(LOG_INFO, "%s:%d -> %s:%d", src, src_port, dst, dst_port);
    }
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = len;
    write_req->data = target;
    uv_udp_send(write_req, &target->target_handle, buf, 1, &target->dest_addr, target_send_cb);
}

static void
resolve_cb(struct sockaddr *addr, void *data) {
    struct target_context *target = data;
    if (addr) {
        target->header_len = addr->sa_family == AF_INET ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
        target->dest_addr = *addr;
        forward_to_target(target, target->buf, target->buflen);

    } else {
        logger_stderr("resolve failed.");
    }
}

static void
resolve_target(struct target_context *target, char *addr, uint16_t port) {
    struct resolver_context *ctx = target->server_handle->loop->data;
    target->addr_query = resolver_query(ctx, addr, port, resolve_cb, target);
}

/*
 *
 * SOCKS5 UDP Request
 * +----+------+------+----------+----------+----------+
 * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 * +----+------+------+----------+----------+----------+
 * | 2  |  1   |  1   | Variable |    2     | Variable |
 * +----+------+------+----------+----------+----------+
 *
 */
static void
client_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread > 0) {
        char host[256] = {0};
        struct sockaddr dest_addr;
        uint8_t frag = (uint8_t)buf->base[2];
        if (frag != 0) {
            logger_log(LOG_ERR, "don't support frag: %d", frag);
            goto err;
        }
        uint8_t atyp = (uint8_t)buf->base[3];
        int addrlen = parse_target_address(atyp, buf->base + 4, &dest_addr, host);
        if (addrlen < 1) {
            logger_log(LOG_ERR, "unsupported address type: 0x%02x", atyp);
            goto err;
        }

        char key[KEY_BYTES + 1] = {0};
        md5((char*)addr, sizeof(*addr), key);

        struct target_context *target = NULL;
        uv_mutex_lock(&mutex);
        cache_lookup(cache, key, (void *)&target);
        uv_mutex_unlock(&mutex);
        if (target == NULL) {
            target = new_target();
            target->client_addr = *addr;
            target->server_handle = handle;
            memcpy(target->key, key, sizeof(key));

            uv_timer_init(handle->loop, target->timer);

            uv_udp_init(handle->loop, &target->target_handle);
            target->target_handle.data = target;
            int rc = uv_udp_recv_start(&target->target_handle, target_alloc_cb, target_recv_cb);
            if (rc) {
                logger_stderr("listen udp target error: %s", uv_strerror(rc));
            }

            uv_mutex_lock(&mutex);
            cache_insert(cache, target->key, (void *)target);
            uv_mutex_unlock(&mutex);
        }
        target->dest_addr = dest_addr;
        reset_timer(target);

        uint16_t port = (*(uint16_t *)(buf->base + 4 + addrlen - 2));
        uint8_t *m = (uint8_t*)buf->base;
        ssize_t mlen = nread - 4 - addrlen;
        memmove(m, m + 4 + addrlen, mlen);

        switch (atyp) {

        case S5_ATYP_IPV4:
        case S5_ATYP_IPV6:
            target->header_len = dest_addr.sa_family == AF_INET ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
            forward_to_target(target, m, mlen);
            break;

        case S5_ATYP_HOST:
            target->buf = m;
            target->buflen = mlen;
            resolve_target(target, host, port);
            break;

        default:
            break;
        }

        return;

    } else {
        goto err;
    }

err:
    free(buf->base);
}

static void
free_cb(void *element) {
    struct target_context *target = (struct target_context *)element;
    close_target(target);
}

static int
select_cb(void *element, void *opaque) {
    struct target_context *target = (struct target_context *)element;
    if (target->server_handle->loop == opaque) {
        return 1;
    }
    return 0;
}

int
udprelay_init() {
    uv_mutex_init(&mutex);
    cache_create(&cache, 1024, free_cb);
    return 0;
}

int
udprelay_start(uv_loop_t *loop, struct server_context *server) {
    int rc;

    uv_udp_init(loop, &server->udp);

    rc = uv_udp_bind(&server->udp, server->local_addr, UV_UDP_REUSEADDR);
    if (rc) {
        logger_stderr("bind error: %s", uv_strerror(rc));
        return 1;
    }

    uv_udp_recv_start(&server->udp, client_alloc_cb, client_recv_cb);

    return 0;
}

void
udprelay_close(struct server_context *server) {
    uv_close((uv_handle_t*) &server->udp, NULL);
    uv_mutex_lock(&mutex);
    cache_removeall(cache, server->udp.loop, select_cb);
    uv_mutex_unlock(&mutex);
}

void
udprelay_destroy() {
    uv_mutex_destroy(&mutex);
    free(cache);
}
