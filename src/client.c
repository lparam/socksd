#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <uv.h>

#include "util.h"
#include "socks.h"
#include "socksd.h"


static void client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void client_send_cb(uv_write_t *req, int status);
static void client_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);


struct client_context *
new_client() {
    struct client_context *client = malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    client->stage = S5_STAGE_HANDSHAKE;
    return client;
}

static void
free_client(struct client_context *client) {
    if (client->remote != NULL) {
        client->remote = NULL;
    }
    free(client);
}

static void
client_close_cb(uv_handle_t *handle) {
    struct client_context *client = (struct client_context *)handle->data;
    free_client(client);
}

void
close_client(struct client_context *client) {
    client->stage = S5_STAGE_DEAD;
    client->handle.handle.data = client;
    uv_close(&client->handle.handle, client_close_cb);
}

static int
verify_methods(char *buf, ssize_t buflen) {
    struct socks5_method_request *req = (struct socks5_method_request *)buf;
    return buflen == 1 + 1 + req->nmethods;
}

static int
verify_request(char *buf, ssize_t buflen) {
    size_t len;
    struct socks5_request *req = (struct socks5_request *)buf;

    if (req->atyp == S5_ATYP_IPV4) {
        len = sizeof(struct socks5_request) + sizeof(struct in_addr) + 2;
    } else if (req->atyp == S5_ATYP_HOST) {
        uint8_t name_len = *(uint8_t *)(req->addr);
        len = sizeof(struct socks5_request) + 1 + name_len + 2;
    } else if (req->atyp == S5_ATYP_IPV6) {
        len = sizeof(struct socks5_request) + sizeof(struct in6_addr) + 2;
    } else {
        len = 0;
    }

    return len == buflen;
}

static int
analyse_request_addr(struct remote_context *remote, struct socks5_request *req, char *addr) {
    if (req->atyp == S5_ATYP_IPV4) {
        // IPV4
        size_t in_addr_len = sizeof(struct in_addr);
        remote->addr.addr4.sin_family = AF_INET;
        memcpy(&remote->addr.addr4.sin_addr, req->addr, in_addr_len);
        memcpy(&remote->addr.addr4.sin_port, req->addr + in_addr_len, 2);
        uv_inet_ntop(AF_INET, (const void *)(req->addr), addr, INET_ADDRSTRLEN);
    } else if (req->atyp == S5_ATYP_HOST) {
        // Domain name
        uint8_t name_len = *(uint8_t *)(req->addr);
        memcpy(&remote->addr.addr4.sin_port, req->addr + 1 + name_len, 2);
        memcpy(addr, req->addr + 1, name_len);
        addr[name_len] = '\0';
    } else if (req->atyp == S5_ATYP_IPV6) {
        // IPV6
        size_t in6_addr_len = sizeof(struct in6_addr);
        memcpy(&remote->addr.addr6.sin6_addr, req->addr, in6_addr_len);
        memcpy(&remote->addr.addr6.sin6_port, req->addr + in6_addr_len, 2);
        uv_inet_ntop(AF_INET6, (const void *)(req->addr), addr, INET6_ADDRSTRLEN);
    } else {
        return 1;
    }

    return 0;
}

static void
send_to_client(struct client_context *client, char *buf, int buflen) {
    uv_buf_t reply = uv_buf_init(buf, buflen);
    client->write_req.data = client;
    uv_write_t *write_req = malloc(sizeof(*write_req));
    write_req->data = client;
    int rc = uv_write(write_req, &client->handle.stream, &reply, 1, client_send_cb);
    if (rc) {
        LOGE("write to client error: %s", uv_strerror(rc));
    }
}

void
receive_from_client(struct client_context *client) {
    client->handle.stream.data = client;
    uv_read_start(&client->handle.stream, client_alloc_cb, client_recv_cb);
}

void
forward_to_client(struct client_context *client, char *buf, int buflen) {
    send_to_client(client, buf, buflen);
}

void
request_ack(struct client_context *client, enum s5_rep rep) {
    struct remote_context *remote = client->remote;
    char *buf = remote->buf;
    struct sockaddr addr;
    int addrlen = sizeof(addr);
    int buflen;

    buf[0] = 0x05; // ver
    buf[1] = rep;  // rep
    buf[2] = 0x00; // rsv

    memset(&addr, 0, sizeof(addr));
    uv_tcp_getsockname(&remote->handle.tcp, (struct sockaddr *) &addr, &addrlen);
    if (addrlen == sizeof(struct sockaddr_in6)) {
        buf[3] = 0x04;  /* atyp - IPv6. */
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)&addr;
        memcpy(buf + 4, &addr6->sin6_addr, 16); /* BND.ADDR */
        memcpy(buf + 20, &addr6->sin6_port, 2); /* BND.PORT */
        buflen = 22;
    } else {
        buf[3] = 0x01;  /* atyp - IPv4. */
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)&addr;
        memcpy(buf + 4, &addr4->sin_addr, 4); /* BND.ADDR */
        memcpy(buf + 8, &addr4->sin_port, 2); /* BND.PORT */
        buflen = 10;
    }

    if (rep == S5_REP_SUCCESSED) {
        client->stage = S5_STAGE_FORWARD;
    } else {
        client->stage = S5_STAGE_TERMINATE;
    }

    send_to_client(client, buf, buflen);
}

static void
handshake(struct client_context *client) {
    client->stage = S5_STAGE_REQUEST;
    send_to_client(client, "\x5\x0", 2);
}

static void
request_start(struct client_context *client) {
    struct socks5_request *request = (struct socks5_request *)client->buf;
    struct remote_context *remote = client->remote;

    if (request->cmd != S5_CMD_CONNECT) {
        LOGE("unsupported cmd: 0x%02x", request->cmd);
        request_ack(client, S5_REP_CMD_NOT_SUPPORTED);
        return;
    }

    char addr[256] = {0};
    int rc = analyse_request_addr(client->remote, request, addr);
    if (rc) {
        LOGE("unsupported address type: 0x%02x", request->atyp);
        request_ack(client, S5_REP_ADDRESS_TYPE_NOT_SUPPORTED);
        return;
    }

    switch (request->atyp) {
        case S5_ATYP_HOST:
            resolve_remote(remote, addr);
            break;
        case S5_ATYP_IPV4:
        case S5_ATYP_IPV6:
            if (verbose) {
                LOGI("connect to %s", addr);
            }
            connect_to_remote(remote);
            break;
        default:
            break;
    }
}

static void
client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct client_context *client = handle->data;
    buf->base = client->buf;
    buf->len = sizeof(client->buf);
}

static void
client_send_cb(uv_write_t *req, int status) {
    struct client_context *client = req->data;
    struct remote_context *remote = client->remote;

    if (status == 0) {
        if (client->stage == S5_STAGE_FORWARD) {
            reset_timer(remote);
            receive_from_remote(remote);
        } else if (client->stage == S5_STAGE_TERMINATE) {
            close_client(client);
            close_remote(remote);
        }

    } else {
        if (verbose) {
            LOGE("send to client failed: %s", uv_strerror(status));
        }
    }

    free(req);
}

static void
client_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client_context *client = stream->data;
    struct remote_context *remote = client->remote;

    if (nread > 0) {
        switch (client->stage) {
        case S5_STAGE_HANDSHAKE:
            if (verify_methods(client->buf, nread)) {
                handshake(client);
            } else {
                LOGE("invalid method packet");
                close_client(client);
                close_remote(remote);
            }
            break;
        case S5_STAGE_REQUEST:
            if (verify_request(client->buf, nread)) {
                request_start(client);
            } else {
                LOGE("invalid request packet");
                close_client(client);
                close_remote(remote);
            }
            break;
        case S5_STAGE_FORWARD:
            uv_read_stop(&client->handle.stream);
            forward_to_remote(remote, buf->base, nread);
            break;
        default:
            break;
        }

    } else if (nread < 0) {
        close_client(client);
        close_remote(remote);
    }
}

void
client_accept_cb(uv_stream_t *server, int status) {
    struct client_context *client = new_client();
    struct remote_context *remote = new_remote(idle_timeout);
    client->remote = remote;
    remote->client = client;

    uv_timer_init(server->loop, remote->timer);

    uv_tcp_init(server->loop, &client->handle.tcp);
    uv_tcp_init(server->loop, &remote->handle.tcp);

    int rc = uv_accept(server, &client->handle.stream);
    if (rc == 0) {
        reset_timer(remote);
        client->handle.stream.data = client;
        rc = uv_read_start(&client->handle.stream, client_alloc_cb, client_recv_cb);
    } else {
        LOGE("accept error: %s", uv_strerror(rc));
        close_client(client);
        close_remote(remote);
    }
}
