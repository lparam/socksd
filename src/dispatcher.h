#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include "uv.h"
#include "consumer.h"

struct signal_ctx {
  uv_signal_t sig;
  int signum;
};

struct ipc_peer_ctx {
    handle_storage_t peer_handle;
    uv_write_t write_req;
};

void dispatcher_start(struct sockaddr *addr, struct server_ctx *servers, uint32_t num_servers);

#endif // for #ifndef _DISPATCHER_H
