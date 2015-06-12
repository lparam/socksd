#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include "uv.h"
#include "util.h"
#include "common.h"
#include "logger.h"
#include "resolver.h"
#include "udprelay.h"
#include "consumer.h"
#include "dispatcher.h"
#include "daemon.h"
#include "socksd.h"


#define MAX_DNS_NUM 4

extern int signal_process(char *signal, const char *pidfile);

static int daemon_mode = 1;
static int concurrency = 0;
static int nameserver_num = 0;
static char *nameservers[MAX_DNS_NUM];
static char *local_addrbuf = "0.0.0.0:1080";
static char *pidfile = "socksd.pid";
static char *xsignal;
static struct signal_ctx signals[3];

static const char *_optString = "l:c:d:p:t:s:nVvh";
static const struct option _lopts[] = {
    { "",        required_argument,   NULL, 'p' },
    { "",        required_argument,   NULL, 'c' },
    { "",        required_argument,   NULL, 'd' },
    { "",        required_argument,   NULL, 't' },
    { "",        required_argument,   NULL, 's' },
    { "",        no_argument,   NULL, 'n' },
    { "version", no_argument,   NULL, 'v' },
    { "help",    no_argument,   NULL, 'h' },
    { "",        no_argument,   NULL, 'V' },
    { NULL,      no_argument,   NULL,  0  }
};

static void
print_usage(const char *prog) {
    printf("socksd Version: %s Maintained by Ken <ken.i18n@gmail.com>\n", SOCKSD_VER);
    printf("Usage: %s [-l bind] [-p pidfile] [-c concurrency] [-t timeout] -s [signal] [-nhvV]\n\n", prog);
    printf("Options:\n");
    puts("  -h, --help\t\t : this help\n"
         "  -l <bind address>\t : bind address:port default(0.0.0.0:1080)\n"
         "  -c <concurrency>\t : worker threads\n"
         "  -d <dns>\t\t : name servers for internal DNS resolver\n"
         "  -p <pidfile>\t\t : pid file path (default: ./socksd.pid)\n"
         "  -t <timeout>\t\t : connection timeout in senconds\n"
	     "  -s <signal>\t\t : send signal to socksd: quit, stop\n"
	     "  -n\t\t\t : non daemon mode\n"
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
        case 'l':
            local_addrbuf = optarg;
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
            pidfile = optarg;
            break;
		case 'n':
            daemon_mode = 0;
			break;
		case 's':
            xsignal = optarg;
            if (strcmp(xsignal, "stop") == 0
              || strcmp(xsignal, "quit") == 0) {
                break;
            }
            fprintf(stderr, "invalid option: -s %s\n", xsignal);
			print_usage(argv[0]);
			break;
        case 't':
            idle_timeout = strtol(optarg, NULL, 10);
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
    if (signum == SIGINT || signum == SIGQUIT) {
        char *name = signum == SIGINT ? "SIGINT" : "SIGQUIT";
        logger_log(LOG_INFO, "Received %s, scheduling shutdown...", name);
        for (int i = 0; i < 2; i++) {
            uv_signal_stop(&signals[i].sig);
        }

        struct resolver_context *dns = uv_key_get(&thread_resolver_key);
        resolver_shutdown(dns);
        struct server_context *ctx = handle->data;
        uv_close((uv_handle_t *)&ctx->tcp, NULL);
        udprelay_close(ctx);
    }
    if (signum == SIGTERM) {
        logger_log(LOG_INFO, "Received SIGTERM, scheduling shutdown...");
        exit(0);
    }
}

void
setup_signal(uv_loop_t *loop, uv_signal_cb cb, void *data) {
    signals[0].signum = SIGINT;
    signals[1].signum = SIGQUIT;
    signals[2].signum = SIGTERM;
    for (int i = 0; i < 2; i++) {
        signals[i].sig.data = data;
        uv_signal_init(loop, &signals[i].sig);
        uv_signal_start(&signals[i].sig, cb, signals[i].signum);
    }
}

static void
init(void) {
    logger_init(daemon_mode);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGPIPE, SIG_IGN);

    resolver_prepare(nameserver_num);

    if (idle_timeout == 0) {
        idle_timeout = 60;
    }
}

int
main(int argc, char *argv[]) {
    int rc;
    uv_loop_t *loop;
    struct sockaddr local_addr;

    parse_opts(argc, argv);

    if (xsignal) {
        return signal_process(xsignal, pidfile);
    }

    init();

    if (daemon_mode) {
        if (daemonize()) {
            return 1;
        }
        if (already_running(pidfile)) {
            logger_stderr("socksd already running.");
            return 1;
        }
    }

    loop = uv_default_loop();

    rc = resolve_addr(local_addrbuf, &local_addr);
    if (rc) {
        logger_stderr("invalid local address");
        return 1;
    }

    udprelay_init();

    if (concurrency <= 1) {
        struct server_context ctx;
        ctx.local_addr = &local_addr;
        ctx.udprelay = 1;

        uv_tcp_init(loop, &ctx.tcp);
        rc = uv_tcp_bind(&ctx.tcp, &local_addr, 0);
        rc = uv_listen((uv_stream_t*)&ctx.tcp, 128, client_accept_cb);
        if (rc == 0) {
            logger_log(LOG_INFO, "listening at %s", local_addrbuf);

            setup_signal(loop, signal_cb, &ctx);

            struct resolver_context *dns =
              resolver_init(loop, MODE_IPV4,
                nameserver_num == 0 ? NULL : nameservers, nameserver_num);
            uv_key_create(&thread_resolver_key);
            uv_key_set(&thread_resolver_key, dns);

            udprelay_start(loop, &ctx);

            uv_run(loop, UV_RUN_DEFAULT);

            close_loop(loop);
            resolver_destroy(dns);
            uv_key_delete(&thread_resolver_key);

        } else {
            logger_stderr("listen error: %s", uv_strerror(rc));
        }

    } else {
        listener_event_loops = calloc(concurrency, sizeof(uv_loop_t));
        listener_async_handles = calloc(concurrency, sizeof(uv_async_t));
        listeners_created_barrier = malloc(sizeof(uv_barrier_t));
        uv_async_t *service_handle = malloc(sizeof(uv_async_t));

        uv_barrier_init(listeners_created_barrier, concurrency + 1);
        uv_async_init(loop, service_handle, NULL);

        struct server_context *servers = calloc(concurrency, sizeof(servers[0]));
        for (int i = 0; i < concurrency; i++) {
            struct server_context *ctx = servers + i;
            ctx->index = i;
            ctx->udprelay = 1;
            ctx->local_addr = &local_addr;
            ctx->accept_cb = client_accept_cb;
            ctx->nameservers = nameservers;
            ctx->nameserver_num = nameserver_num;
            rc = uv_sem_init(&ctx->semaphore, 0);
            rc = uv_thread_create(&ctx->thread_id, consumer_start, ctx);
        }

        uv_barrier_wait(listeners_created_barrier);
        dispatcher_start(&local_addr, servers, concurrency);

        free(listener_event_loops);
        free(listener_async_handles);
        free(listeners_created_barrier);
        free(service_handle);
        free(servers);
    }

    udprelay_destroy();

    if (daemon_mode) {
        delete_pidfile(pidfile);
    }

    return 0;
}
