#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include <uv.h>

#include "util.h"
#include "resolver.h"
#include "socksd.h"
#include "consumer.h"
#include "dispatcher.h"


#define MAX_DNS_NUM 4

static uint16_t port = 1080;
static int concurrency = 0;
static int nameserver_num = 0;
static char *nameservers[MAX_DNS_NUM];

static const char *_optString = "c:d:p:t:Vvh";
static const struct option _lopts[] = {
    { "",        required_argument,   NULL, 'p' },
    { "",        required_argument,   NULL, 'c' },
    { "",        required_argument,   NULL, 'd' },
    { "",        required_argument,   NULL, 't' },
    { "version", no_argument,   NULL, 'v' },
    { "help",    no_argument,   NULL, 'h' },
    { "",        no_argument,   NULL, 'V' },
    { NULL,      no_argument,   NULL,  0  }
};

static void
print_usage(const char *prog) {
    printf("socksd Version: %s Maintained by Ken <ken.i18n@gmail.com>\n", SOCKSD_VER);
    printf("Usage: %s [-p port] [-c concurrency] [-t timeout] [-hvV]\n\n", prog);
    printf("Options:\n");
    puts("  -h, --help\t\t : this help\n"
         "  -p <port>\t\t : server port\n"
         "  -c <concurrency>\t : worker threads\n"
         "  -d <dns>\t\t : name servers for internal DNS resolver\n"
         "  -t <timeout>\t\t : connection timeout in senconds\n"
         "  -v, --version\t\t : show version\n"
         "  -V \t\t\t : verbose mode\n");

    exit(1);
}

static void
parse_opts(int argc, char *argv[]) {
    int opt = 0, longindex = 0;

    while ((opt = getopt_long(argc, argv, _optString, _lopts, &longindex)) != -1) {
        switch (opt) {
        case 'v':
            printf("socksd version: %s \n", SOCKSD_VER);
            exit(0);
            break;
        case 'h':
        case '?':
            print_usage(argv[0]);
            break;
        case 'c':
            concurrency = strtol(optarg, NULL, 10);
            break;
        case 'd':
            if (nameserver_num < MAX_DNS_NUM) {
                nameservers[nameserver_num++] = optarg;
            }
            break;
        case 'p':
            port = strtol(optarg, NULL, 10);
            break;
        case 't':
            idle_timeout = strtol(optarg, NULL, 10) * 1000;
            break;
        case 'V':
            verbose = 1;
            break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
}

static void
close_walk_cb(uv_handle_t *handle, void *arg) {
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
}

void
close_loop(uv_loop_t *loop) {
    uv_walk(loop, close_walk_cb, NULL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
}

static void
signal_cb(uv_signal_t *handle, int signum) {
    if (signum == SIGINT) {
        LOGI("Received SIGINT, scheduling shutdown...");

        uv_signal_stop(handle);

        struct resolver_context *res = handle->loop->data;
        resolver_shutdown(res);

        uv_tcp_t *server = handle->data;
        uv_close((uv_handle_t*)server, NULL);
    }
}

static void
init(void) {
    env_resolver = getenv("RESOLVER");

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGPIPE, SIG_IGN);

    resolver_prepare(nameserver_num);

    if (idle_timeout == 0) {
        idle_timeout = 60 * 1000;
    }
}

int
main(int argc, char *argv[]) {
    int rc;
    uv_loop_t *uv_loop;
    struct sockaddr bind_addr;

    parse_opts(argc, argv);

    init();

    uv_loop = uv_default_loop();

    char addr[16] = {0};
    snprintf(addr, sizeof addr, "0.0.0.0:%u", port);
    rc = resolve_addr(addr, &bind_addr);
    if (rc) {
        return 1;
    }

    if (concurrency <= 1) {
        uv_tcp_t server;
        uv_tcp_init(uv_loop, &server);
        rc = uv_tcp_bind(&server, &bind_addr, 0);
        rc = uv_listen((uv_stream_t*)&server, 128, client_accept_cb);
        if (rc == 0) {
            LOGI("listening at port %u", port);

            uv_signal_t sigint;
            sigint.data = &server;
            uv_signal_init(uv_loop, &sigint);
            uv_signal_start(&sigint, signal_cb, SIGINT);

            struct resolver_context *res = resolver_init(uv_loop, MODE_IPV4,
              nameserver_num == 0 ? NULL : nameservers, nameserver_num);
            uv_loop->data = res;

            uv_run(uv_loop, UV_RUN_DEFAULT);

            close_loop(uv_loop);
            resolver_destroy(res);

        } else {
            LOGE("listen error: %s", uv_strerror(rc));
        }
    } else {
        listener_event_loops = calloc(concurrency, sizeof(uv_loop_t));
        listener_async_handles = calloc(concurrency, sizeof(uv_async_t));
        listeners_created_barrier = malloc(sizeof(uv_barrier_t));
        uv_async_t *service_handle = malloc(sizeof(uv_async_t));

        uv_barrier_init(listeners_created_barrier, concurrency + 1);
        uv_async_init(uv_loop, service_handle, NULL);

        struct server_ctx *servers = calloc(concurrency, sizeof(servers[0]));
        for (int i = 0; i < concurrency; i++) {
            struct server_ctx *ctx = servers + i;
            ctx->index = i;
            ctx->accept_cb = client_accept_cb;
            ctx->nameservers = nameservers;
            ctx->nameserver_num = nameserver_num;
            rc = uv_sem_init(&ctx->semaphore, 0);
            rc = uv_thread_create(&ctx->thread_id, consumer_start, ctx);
        }

        uv_barrier_wait(listeners_created_barrier);
        dispatcher_start(&bind_addr, servers, concurrency);

        free(listener_event_loops);
        free(listener_async_handles);
        free(listeners_created_barrier);
        free(service_handle);
        free(servers);
    }

    return 0;
}
