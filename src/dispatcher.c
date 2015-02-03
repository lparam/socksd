#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "dispatcher.h"
#include "consumer.h"


extern void close_loop(uv_loop_t *loop);
extern void setup_signal(uv_loop_t *loop, uv_signal_cb cb, void *data);

static void
ipc_close_cb(uv_handle_t* handle) {
    struct ipc_peer_ctx* ctx;
    ctx = container_of(handle, struct ipc_peer_ctx, peer_handle);
    free(ctx);
}

static void
ipc_write_cb(uv_write_t* req, int status) {
    struct ipc_peer_ctx* ctx;
    ctx = container_of(req, struct ipc_peer_ctx, write_req);
    uv_close((uv_handle_t*) &ctx->peer_handle, ipc_close_cb);
}

static void
ipc_connection_cb(uv_stream_t* ipc_pipe, int status) {
    struct ipc_server_ctx* sc;
    struct ipc_peer_ctx* pc;
    uv_loop_t* loop;
    uv_buf_t buf;

    loop = ipc_pipe->loop;
    buf = uv_buf_init("PING", 4);
    sc = container_of(ipc_pipe, struct ipc_server_ctx, ipc_pipe);
    pc = calloc(1, sizeof(*pc));

    if (ipc_pipe->type == UV_TCP) {
        uv_tcp_init(loop, (uv_tcp_t*) &pc->peer_handle);
    } else if (ipc_pipe->type == UV_NAMED_PIPE) {
        uv_pipe_init(loop, (uv_pipe_t*) &pc->peer_handle, 1);
    }

    uv_accept(ipc_pipe, (uv_stream_t*) &pc->peer_handle);
    uv_write2(&pc->write_req,
                          (uv_stream_t*) &pc->peer_handle,
                          &buf,
                          1,
                          (uv_stream_t*) &sc->server_handle,
                          ipc_write_cb);

    if (--sc->num_connects == 0) {
        uv_close((uv_handle_t*)ipc_pipe, NULL);
    }
}

static void
signal_cb(uv_signal_t *handle, int signum) {
    struct ipc_server_ctx *ipc = handle->data;
    if (signum == SIGINT || signum == SIGQUIT) {
        char *name = signum == SIGINT ? "SIGINT" : "SIGQUIT";
        logger_log(LOG_INFO, "Received %s, scheduling shutdown...", name);
        for (int i = 0; i < ipc->num_servers; i++) {
            struct server_ctx *server = &ipc->servers[i];
            uv_async_send(&server->async_handle);
        }
        uv_stop(handle->loop);
    }
    if (signum == SIGTERM) {
        logger_log(LOG_WARNING, "Received SIGTERM, scheduling shutdown...");
        exit(0);
    }
}

void
dispatcher_start(struct sockaddr *addr, struct server_ctx *servers, uint32_t num_servers) {
    int rc;
    unsigned int i;
    uv_loop_t *loop;
    struct ipc_server_ctx ctx;

    loop = uv_default_loop();

    ctx.num_connects = num_servers;
    ctx.num_servers = num_servers;
    ctx.servers = servers;

    uv_tcp_init(loop, (uv_tcp_t*) &ctx.server_handle);
    rc = uv_tcp_bind((uv_tcp_t*) &ctx.server_handle, (const struct sockaddr*)addr, 0);
    if (rc || errno) {
        logger_stderr("listen error: %s", rc ? uv_strerror(rc) : strerror(errno));
        exit(1);
    }

    char ip[INET6_ADDRSTRLEN + 1];
    int port = ip_name(addr, ip, sizeof(ip));
    logger_log(LOG_INFO, "listening on %s:%d", ip, port);

    uv_pipe_init(loop, &ctx.ipc_pipe, 1);
    unlink(IPC_PIPE_NAME);
    rc = uv_pipe_bind(&ctx.ipc_pipe, IPC_PIPE_NAME);
    if (rc) {
        logger_stderr("create pipe error: %s", uv_strerror(rc));
        exit(1);
    }
    uv_listen((uv_stream_t*) &ctx.ipc_pipe, 128, ipc_connection_cb);

    for (i = 0; i < num_servers; i++) {
        uv_sem_post(&servers[i].semaphore);
    }

    setup_signal(loop, signal_cb, &ctx);

    uv_run(loop, UV_RUN_DEFAULT);

    close_loop(loop);

    for (i = 0; i < num_servers; i++) {
        uv_sem_wait(&servers[i].semaphore);
    }
}
