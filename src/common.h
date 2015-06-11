#ifndef _COMMON_H
#define _COMMON_H

#include "uv.h"


union stream_handle2 {
    uv_pipe_t pipe;
    uv_tcp_t tcp;
};

typedef unsigned char handle_storage_t[sizeof(union stream_handle2)];

struct server_context {
    int index;
    handle_storage_t server_handle;
    unsigned int num_connects;
    uv_async_t async_handle;
    uv_thread_t thread_id;
    uv_sem_t semaphore;
    uv_connection_cb accept_cb;
    int nameserver_num;
    char **nameservers;
    uv_tcp_t tcp;
    uv_udp_t udp;
    int udprelay;
    struct sockaddr *local_addr;
};

#endif // for #ifndef _COMMON_H
