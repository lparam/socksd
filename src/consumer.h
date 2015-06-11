#ifndef _CONSUMER_H
#define _CONSUMER_H

#include "uv.h"
#include "util.h"
#include "common.h"

#define IPC_PIPE_NAME "SOCKSD_CONNECTION_DISPATCHER_PIPE"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

// #define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))

struct ipc_client_ctx {
    uv_connect_t connect_req;
    uv_stream_t* server_handle;
    uv_pipe_t ipc_pipe;
    char scratch[16];
};

struct ipc_server_ctx {
    handle_storage_t server_handle;
    unsigned int num_connects;
    unsigned int num_servers;
    struct server_context *servers;
    uv_pipe_t ipc_pipe;
};

uv_loop_t *listener_event_loops;
uv_async_t *listener_async_handles;
uv_barrier_t *listeners_created_barrier;
void consumer_start(void *arg);

#endif // for #ifndef _CONSUMER_H
