/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    int client_fd; // Used for CMD_RUN waiting
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/*
 * TODO:
 * Implement producer-side insertion into the bounded buffer.
 *
 * Requirements:
 *   - block or fail according to your chosen policy when the buffer is full
 *   - wake consumers correctly
 *   - stop cleanly if shutdown begins
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
    }

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);

    return 0;
}

/*
 * TODO:
 * Implement consumer-side removal from the bounded buffer.
 *
 * Requirements:
 *   - wait correctly while the buffer is empty
 *   - return a useful status when shutdown is in progress
 *   - avoid races with producers and shutdown
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == 0 && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }

    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);

    return 0;
}

/*
 * TODO:
 * Implement the logging consumer thread.
 *
 * Suggested responsibilities:
 *   - remove log chunks from the bounded buffer
 *   - route each chunk to the correct per-container log file
 *   - exit cleanly when shutdown begins and pending work is drained
 */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;

    mkdir(LOG_DIR, 0755);

    while (1) {
        if (bounded_buffer_pop(&ctx->log_buffer, &item) != 0) {
            break; // Shutdown signaled and buffer drained
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);

        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, item.data, item.length);
            close(fd);
        }
    }

    return NULL;
}

/*
 * TODO:
 * Implement the clone child entrypoint.
 *
 * Required outcomes:
 *   - isolated PID / UTS / mount context
 *   - chroot or pivot_root into rootfs
 *   - working /proc inside container
 *   - stdout / stderr redirected to the supervisor logging path
 *   - configured command executed inside the container
 */
int child_fn(void *arg)
{
    child_config_t *config = (child_config_t *)arg;

    // Set hostname
    sethostname(config->id, strlen(config->id));

    // Redirect stdout and stderr to the logging pipe
    if (config->log_write_fd >= 0) {
        dup2(config->log_write_fd, STDOUT_FILENO);
        dup2(config->log_write_fd, STDERR_FILENO);
        close(config->log_write_fd);
    }

    // Set priority
    setpriority(PRIO_PROCESS, 0, config->nice_value);

    // Setup mount namespace and rootfs
    // Ensure the rootfs doesn't have MS_SHARED propagated
    mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);

    // Bind mount the container rootfs to itself so it's a mount point
    if (mount(config->rootfs, config->rootfs, "bind", MS_BIND | MS_REC, NULL) != 0) {
        perror("mount bind rootfs");
        return 1;
    }

    // chdir into the new root
    if (chdir(config->rootfs) != 0) {
        perror("chdir rootfs");
        return 1;
    }

    // mount proc
    mkdir("proc", 0755);
    if (mount("proc", "proc", "proc", 0, NULL) != 0) {
        perror("mount proc");
        return 1;
    }

    // pivot_root
    mkdir("oldroot", 0755);
    if (syscall(SYS_pivot_root, ".", "oldroot") != 0) {
        perror("pivot_root");
        return 1;
    }

    chdir("/");

    // unmount oldroot
    umount2("/oldroot", MNT_DETACH);
    rmdir("/oldroot");

    // Execute the command
    char *args[] = {"/bin/sh", "-c", config->command, NULL};
    execvp(args[0], args);

    perror("execvp");
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

static volatile sig_atomic_t g_stop_supervisor = 0;

static void sigint_handler(int signum) {
    (void)signum;
    g_stop_supervisor = 1;
}

static void sigchld_handler(int signum) {
    (void)signum;
    // We will reap in the main loop to handle metadata updates
}

static void *producer_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    char buffer[LOG_CHUNK_SIZE];
    ssize_t n;

    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        // Find container_id from fd (Requires passing it properly, a bit hacky but we'll do it later)
        // Actually, we can read chunks directly and send them to bounded buffer.
        // Needs a struct to hold container_id and fd.
    }
    close(fd);
    return NULL;
}

typedef struct {
    int fd;
    char container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *buffer;
} producer_ctx_t;

static void *container_producer_thread(void *arg) {
    producer_ctx_t *ctx = (producer_ctx_t *)arg;
    char buffer[LOG_CHUNK_SIZE];
    ssize_t n;

    while ((n = read(ctx->fd, buffer, sizeof(buffer))) > 0) {
        log_item_t item;
        strncpy(item.container_id, ctx->container_id, CONTAINER_ID_LEN);
        item.length = n;
        memcpy(item.data, buffer, n);
        bounded_buffer_push(ctx->buffer, &item);
    }

    close(ctx->fd);
    free(ctx);
    return NULL;
}

/*
 * TODO:
 * Implement the long-running supervisor process.
 *
 * Suggested responsibilities:
 *   - create and bind the control-plane IPC endpoint
 *   - initialize shared metadata and the bounded buffer
 *   - start the logging thread
 *   - accept control requests and update container state
 *   - reap children and respond to signals
 */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    int rc;
    struct sockaddr_un addr;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;

    (void)rootfs; // Not explicitly doing anything with it right now

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0) {
        perror("open /dev/container_monitor");
        // Still run but without kernel monitor
    }

    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(ctx.server_fd, 10) < 0) {
        perror("listen");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE for socket writes

    pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);

    // Event loop using epoll/select
    fd_set read_fds;
    int max_fd;

    while (!g_stop_supervisor) {
        FD_ZERO(&read_fds);
        FD_SET(ctx.server_fd, &read_fds);
        max_fd = ctx.server_fd;

        struct timeval tv = {1, 0}; // 1 sec timeout for regular SIGCHLD checks

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (activity < 0 && errno != EINTR) {
            perror("select error");
            break;
        }

        // Handle reaped children
        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            pthread_mutex_lock(&ctx.metadata_lock);
            container_record_t *curr = ctx.containers;
            while (curr) {
                if (curr->host_pid == pid) {
                    if (WIFEXITED(status)) {
                        curr->state = CONTAINER_EXITED;
                        curr->exit_code = WEXITSTATUS(status);
                    } else if (WIFSIGNALED(status)) {
                        curr->exit_signal = WTERMSIG(status);
                        curr->exit_code = 128 + curr->exit_signal;
                        if (curr->state == CONTAINER_STOPPED) {
                            // Manual stop
                        } else if (curr->exit_signal == SIGKILL) {
                            curr->state = CONTAINER_KILLED;
                        } else {
                            curr->state = CONTAINER_EXITED;
                        }
                    }
                    if (ctx.monitor_fd >= 0) {
                        unregister_from_monitor(ctx.monitor_fd, curr->id, curr->host_pid);
                    }

                    if (curr->client_fd >= 0) {
                        control_response_t resp;
                        memset(&resp, 0, sizeof(resp));
                        resp.status = curr->exit_code;
                        snprintf(resp.message, sizeof(resp.message), "Container exited with code: %d", curr->exit_code);
                        write(curr->client_fd, &resp, sizeof(resp));
                        close(curr->client_fd);
                        curr->client_fd = -1;
                    }
                    break;
                }
                curr = curr->next;
            }
            pthread_mutex_unlock(&ctx.metadata_lock);
        }

        if (activity > 0 && FD_ISSET(ctx.server_fd, &read_fds)) {
            int client_fd = accept(ctx.server_fd, NULL, NULL);
            if (client_fd >= 0) {
                control_request_t req;
                control_response_t resp;
                memset(&resp, 0, sizeof(resp));

                if (read(client_fd, &req, sizeof(req)) == sizeof(req)) {
                    if (req.kind == CMD_START || req.kind == CMD_RUN) {
                        int pipe_fds[2];
                        pipe(pipe_fds);

                        child_config_t *child_cfg = malloc(sizeof(child_config_t));
                        strncpy(child_cfg->id, req.container_id, CONTAINER_ID_LEN);
                        strncpy(child_cfg->rootfs, req.rootfs, PATH_MAX);
                        strncpy(child_cfg->command, req.command, CHILD_COMMAND_LEN);
                        child_cfg->nice_value = req.nice_value;
                        child_cfg->log_write_fd = pipe_fds[1];

                        void *stack = malloc(STACK_SIZE);
                        pid_t child_pid = clone(child_fn, (char *)stack + STACK_SIZE,
                                                SIGCHLD | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS, child_cfg);

                        if (child_pid < 0) {
                            resp.status = 1;
                            snprintf(resp.message, sizeof(resp.message), "Failed to clone container");
                            write(client_fd, &resp, sizeof(resp));
                            close(client_fd);
                            free(child_cfg);
                            free(stack);
                            continue;
                        }

                        close(pipe_fds[1]);

                        producer_ctx_t *prod_ctx = malloc(sizeof(producer_ctx_t));
                        prod_ctx->fd = pipe_fds[0];
                        strncpy(prod_ctx->container_id, req.container_id, CONTAINER_ID_LEN);
                        prod_ctx->buffer = &ctx.log_buffer;

                        pthread_t prod_tid;
                        pthread_create(&prod_tid, NULL, container_producer_thread, prod_ctx);
                        pthread_detach(prod_tid);

                        container_record_t *rec = malloc(sizeof(container_record_t));
                        memset(rec, 0, sizeof(*rec));
                        strncpy(rec->id, req.container_id, CONTAINER_ID_LEN);
                        rec->host_pid = child_pid;
                        rec->started_at = time(NULL);
                        rec->state = CONTAINER_RUNNING;
                        rec->soft_limit_bytes = req.soft_limit_bytes;
                        rec->hard_limit_bytes = req.hard_limit_bytes;
                        rec->client_fd = -1;
                        snprintf(rec->log_path, PATH_MAX, "%s/%s.log", LOG_DIR, rec->id);

                        pthread_mutex_lock(&ctx.metadata_lock);
                        rec->next = ctx.containers;
                        ctx.containers = rec;
                        pthread_mutex_unlock(&ctx.metadata_lock);

                        if (ctx.monitor_fd >= 0) {
                            register_with_monitor(ctx.monitor_fd, rec->id, rec->host_pid, rec->soft_limit_bytes, rec->hard_limit_bytes);
                        }

                        if (req.kind == CMD_START) {
                            resp.status = 0;
                            snprintf(resp.message, sizeof(resp.message), "Container started: %s (PID: %d)", req.container_id, child_pid);
                            write(client_fd, &resp, sizeof(resp));
                            close(client_fd);
                        } else {
                            // Let the main event loop handle the close of client_fd. Wait for SIGCHLD.
                            // However, we are using epoll/select, we can't block here.
                            // Instead, store client_fd in container_record_t.
                            pthread_mutex_lock(&ctx.metadata_lock);
                            rec->client_fd = client_fd;
                            pthread_mutex_unlock(&ctx.metadata_lock);
                        }
                    } else if (req.kind == CMD_PS) {
                        pthread_mutex_lock(&ctx.metadata_lock);
                        container_record_t *curr = ctx.containers;
                        while (curr) {
                            char buf[256];
                            snprintf(buf, sizeof(buf), "ID: %s, PID: %d, State: %s\n", curr->id, curr->host_pid, state_to_string(curr->state));
                            resp.status = 0;
                            strncpy(resp.message, buf, sizeof(resp.message));
                            write(client_fd, &resp, sizeof(resp));
                            curr = curr->next;
                        }
                        pthread_mutex_unlock(&ctx.metadata_lock);

                        resp.status = 0;
                        resp.message[0] = '\0';
                        write(client_fd, &resp, sizeof(resp));
                        close(client_fd);
                    } else if (req.kind == CMD_LOGS) {
                        char path[PATH_MAX];
                        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, req.container_id);
                        int log_fd = open(path, O_RDONLY);
                        if (log_fd >= 0) {
                            char buf[CONTROL_MESSAGE_LEN];
                            ssize_t n;
                            while ((n = read(log_fd, buf, sizeof(buf) - 1)) > 0) {
                                buf[n] = '\0';
                                strncpy(resp.message, buf, sizeof(resp.message));
                                resp.status = 0;
                                write(client_fd, &resp, sizeof(resp));
                            }
                            close(log_fd);
                        }
                        resp.status = 0;
                        resp.message[0] = '\0';
                        write(client_fd, &resp, sizeof(resp));
                        close(client_fd);
                    } else if (req.kind == CMD_STOP) {
                        int found = 0;
                        pthread_mutex_lock(&ctx.metadata_lock);
                        container_record_t *curr = ctx.containers;
                        while (curr) {
                            if (strcmp(curr->id, req.container_id) == 0 && curr->state == CONTAINER_RUNNING) {
                                curr->state = CONTAINER_STOPPED;
                                kill(curr->host_pid, SIGTERM);
                                found = 1;
                                break;
                            }
                            curr = curr->next;
                        }
                        pthread_mutex_unlock(&ctx.metadata_lock);

                        if (found) {
                            resp.status = 0;
                            snprintf(resp.message, sizeof(resp.message), "Container %s stopped", req.container_id);
                        } else {
                            resp.status = 1;
                            snprintf(resp.message, sizeof(resp.message), "Container %s not found or not running", req.container_id);
                        }
                        write(client_fd, &resp, sizeof(resp));
                        close(client_fd);
                    }
                } else {
                    close(client_fd);
                }
            }
        }
    }

    // Cleanup containers
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *curr = ctx.containers;
    while (curr) {
        if (curr->state == CONTAINER_RUNNING) {
            kill(curr->host_pid, SIGKILL);
        }
        container_record_t *next = curr->next;
        free(curr);
        curr = next;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    if (ctx.server_fd >= 0) close(ctx.server_fd);
    unlink(CONTROL_PATH);

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 0;
}

/*
 * TODO:
 * Implement the client-side control request path.
 *
 * The CLI commands should use a second IPC mechanism distinct from the
 * logging pipe. A UNIX domain socket is the most direct option, but a
 * FIFO or shared memory design is also acceptable if justified.
 */
static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    if (write(fd, req, sizeof(*req)) != sizeof(*req)) {
        perror("write");
        close(fd);
        return 1;
    }

    if (req->kind == CMD_RUN) {
        // Run blocks until the container exits
        while (1) {
            int n = read(fd, &resp, sizeof(resp));
            if (n <= 0) break;

            if (resp.message[0] != '\0') {
                printf("%s\n", resp.message);
            }

            if (resp.status != 0) {
                close(fd);
                return resp.status;
            }
        }
    } else if (req->kind == CMD_LOGS || req->kind == CMD_PS) {
        while (1) {
            int n = read(fd, &resp, sizeof(resp));
            if (n <= 0) break;

            if (resp.message[0] != '\0') {
                printf("%s", resp.message); // Note: Server must include \n
            } else {
                break; // Empty message signifies end of stream
            }

            if (resp.status != 0) {
                close(fd);
                return resp.status;
            }
        }
    } else {
        if (read(fd, &resp, sizeof(resp)) > 0) {
            if (resp.message[0] != '\0') {
                printf("%s\n", resp.message);
            }
            if (resp.status != 0) {
                close(fd);
                return resp.status;
            }
        }
    }

    close(fd);
    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    /*
     * TODO:
     * The supervisor should respond with container metadata.
     * Keep the rendering format simple enough for demos and debugging.
     */
    printf("Expected states include: %s, %s, %s, %s, %s\n",
           state_to_string(CONTAINER_STARTING),
           state_to_string(CONTAINER_RUNNING),
           state_to_string(CONTAINER_STOPPED),
           state_to_string(CONTAINER_KILLED),
           state_to_string(CONTAINER_EXITED));
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
