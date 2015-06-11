#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "resolver.h"
#include "socks.h"
#include "socksd.h"


static void remote_send_cb(uv_write_t *req, int status);
static void remote_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);


static void
remote_timer_expire(uv_timer_t *handle) {
    struct remote_context *remote = handle->data;
    struct client_context *client = remote->client;
    if (verbose) {
        if (client->cmd == S5_CMD_UDP_ASSOCIATE) {
            logger_log(LOG_WARNING, "udp assocation timeout");
        } else {
            char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
            uint16_t port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
            logger_log(LOG_WARNING, "%s:%d <-> %s connection timeout", addrbuf, port, client->target_addr);
        }
    }
    request_ack(remote->client, S5_REP_TTL_EXPIRED);
}

void
reset_timer(struct remote_context *remote) {
    if (remote->timer != NULL) {
        remote->timer->data = remote;
        uv_timer_start(remote->timer, remote_timer_expire, remote->idle_timeout, 0);
    }
}

static void
timer_close_cb(uv_handle_t *handle) {
    free(handle);
}

struct remote_context *
new_remote(uint16_t timeout) {
    struct remote_context *remote = malloc(sizeof(*remote));
    memset(remote, 0, sizeof(*remote));
    remote->timer = malloc(sizeof(uv_timer_t));
    remote->idle_timeout = timeout * 1000;
    return remote;
}

static void
free_remote(struct remote_context *remote) {
    if (remote->client != NULL) {
        remote->client = NULL;
    }
    free(remote);
    remote = NULL;
}

static void
remote_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct remote_context *remote = (struct remote_context *)handle->data;
    buf->base = remote->buf;
    buf->len = sizeof(remote->buf);
}

static void
remote_close_cb(uv_handle_t *handle) {
    struct remote_context *remote = handle->data;
    free_remote(remote);
}

void
close_remote(struct remote_context *remote) {
    if (remote->stage == S5_STAGE_RESOLVE) {
        resolver_cancel(remote->addr_query);
    }

    assert(uv_is_closing(&remote->handle.handle) == 0);

    remote->timer->data = NULL;
    uv_close((uv_handle_t *)remote->timer, timer_close_cb);

    remote->timer = NULL;
    remote->stage = S5_STAGE_DEAD;

    remote->handle.handle.data = remote;
    uv_close(&remote->handle.handle, remote_close_cb);
}

static void
remote_connect_cb(uv_connect_t *req, int status) {
    struct remote_context *remote = (struct remote_context *)req->data;
    struct client_context *client = remote->client;

    if (status == 0) {
        reset_timer(remote);
        remote->stage = S5_STAGE_FORWARD;
        request_ack(client, S5_REP_SUCCESSED);
        remote->handle.stream.data = remote;
        uv_read_start(&remote->handle.stream, remote_alloc_cb, remote_recv_cb);
    } else {
        if (status != UV_ECANCELED) {
            logger_log(LOG_ERR, "connect to %s failed: %s", client->target_addr, uv_strerror(status));
            request_ack(client, S5_REP_HOST_UNREACHABLE);
        }
    }
}

void
receive_from_remote(struct remote_context *remote) {
    remote->handle.stream.data = remote;
    uv_read_start(&remote->handle.stream, remote_alloc_cb, remote_recv_cb);
}

void
forward_to_remote(struct remote_context *remote, char *buf, int buflen) {
    uv_buf_t request = uv_buf_init(buf, buflen);
    remote->write_req.data = remote;
    uv_write(&remote->write_req, &remote->handle.stream, &request, 1, remote_send_cb);
}

void
connect_to_remote(struct remote_context *remote) {
    remote->stage = S5_STAGE_CONNECT;
    remote->connect_req.data = remote;
    int rc = uv_tcp_connect(&remote->connect_req, &remote->handle.tcp, &remote->addr, remote_connect_cb);
    if (rc) {
        logger_log(LOG_ERR, "connect to %s error: %s", remote->client->target_addr, uv_strerror(rc));
        request_ack(remote->client, S5_REP_NETWORK_UNREACHABLE);
    }
}

static void
resolve_cb(struct sockaddr *addr, void *data) {
    struct remote_context *remote = data;
    struct client_context *client = remote->client;

    if (addr == NULL) {
        remote->stage = S5_STAGE_TERMINATE;
        request_ack(client, S5_REP_HOST_UNREACHABLE);

    } else {
        remote->addr = *addr;
        if (verbose) {
            logger_log(LOG_INFO, "connect to %s", remote->client->target_addr);
        }
        connect_to_remote(remote);
    }
}

void
resolve_remote(struct remote_context *remote, char *addr, uint16_t port) {
    struct resolver_context *ctx = remote->handle.handle.loop->data;
    remote->stage = S5_STAGE_RESOLVE;
    remote->addr_query = resolver_query(ctx, addr, port, resolve_cb, remote);
}

static void
remote_send_cb(uv_write_t *req, int status) {
    struct remote_context *remote = (struct remote_context *)req->data;
    struct client_context *client = remote->client;

    if (status == 0) {
        reset_timer(remote);
        receive_from_client(client);

    } else {
        if (verbose) {
            char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
            uint16_t port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
            logger_log(LOG_ERR, "%s:%d -> failed: %s", addrbuf, port, client->target_addr, uv_strerror(status));
        }
    }
}

static void
remote_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct remote_context *remote;
    struct client_context *client;

    remote = stream->data;
    client = remote->client;

    if (nread > 0) {
        uv_read_stop(&remote->handle.stream);
        forward_to_client(client, buf->base, nread);
    } else if (nread < 0){
        if (nread != UV_EOF && verbose) {
            logger_log(LOG_ERR, "receive from %s failed: %s", client->target_addr, uv_strerror(nread));
        }
        close_client(client);
        close_remote(remote);
    }
}
