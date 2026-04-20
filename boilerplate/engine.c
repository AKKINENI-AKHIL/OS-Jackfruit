/*
 * engine.c — Supervised Multi-Container Runtime
 *
 * Tasks implemented:
 *   1. Multi-container runtime: clone() with PID/UTS/mount namespaces, chroot
 *   2. Supervisor CLI over UNIX domain socket (Path B IPC) + signal handling
 *   3. Bounded-buffer logging: pipe→producer thread→buffer→consumer thread→file
 *   4. Kernel monitor integration via ioctl, stop_requested attribution rule
 *   5. Scheduling experiments via nice value
 *   6. Clean teardown: thread join, fd close, zombie reap, heap free
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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

/* ------------------------------------------------------------------ */
/* Constants — sizes are consistent across all structs                  */
/* ------------------------------------------------------------------ */
#define STACK_SIZE           (1024 * 1024)
#define CONTAINER_ID_LEN     32
#define CONTROL_PATH         "/tmp/mini_runtime.sock"
#define LOG_DIR              "logs"
#define MSG_LEN              2048   /* message field in wire structs */
#define CHILD_COMMAND_LEN    512
#define LOG_CHUNK_SIZE       (MSG_LEN - 1)  /* max bytes per log push */
#define LOG_BUFFER_CAPACITY  64
#define DEFAULT_SOFT_LIMIT   (40UL << 20)
#define DEFAULT_HARD_LIMIT   (64UL << 20)
#define MONITOR_DEVICE       "/dev/container_monitor"

/* ------------------------------------------------------------------ */
/* Enumerations                                                         */
/* ------------------------------------------------------------------ */
typedef enum {
    CMD_SUPERVISOR = 0, CMD_START, CMD_RUN, CMD_PS, CMD_LOGS, CMD_STOP
} command_kind_t;

/*
 * Container states — shown by `engine ps`.
 * Attribution rule (Task 4):
 *   CONTAINER_STOPPED      → stop_requested set before signal
 *   CONTAINER_HARD_KILLED  → SIGKILL received, stop_requested NOT set
 *   CONTAINER_KILLED       → other signal, stop_requested NOT set
 *   CONTAINER_EXITED       → exited normally (WIFEXITED)
 */
typedef enum {
    CONTAINER_STARTING    = 0,
    CONTAINER_RUNNING     = 1,
    CONTAINER_STOPPED     = 2,   /* operator issued `engine stop`        */
    CONTAINER_HARD_KILLED = 3,   /* kernel hard-limit SIGKILL            */
    CONTAINER_KILLED      = 4,   /* unexpected external signal           */
    CONTAINER_EXITED      = 5    /* normal exit                          */
} container_state_t;

/* ------------------------------------------------------------------ */
/* Structs                                                              */
/* ------------------------------------------------------------------ */

typedef struct container_record {
    char               id[CONTAINER_ID_LEN];
    pid_t              host_pid;
    time_t             started_at;
    container_state_t  state;
    unsigned long      soft_limit_bytes;
    unsigned long      hard_limit_bytes;
    int                nice_value;
    int                exit_code;
    int                exit_signal;
    int                stop_requested;   /* set BEFORE any kill signal */
    char               log_path[PATH_MAX];
    int                pipe_read_fd;
    pthread_t          producer_thread;
    int                producer_started;
    struct container_record *next;
} container_record_t;

typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[MSG_LEN];
} log_item_t;

/*
 * Bounded circular buffer protected by mutex + two CVs.
 *
 * Synchronisation rationale:
 *   mutex    – serialises all access to head/tail/count/shutting_down.
 *   not_full – producers wait here when count == capacity.
 *   not_empty– consumers wait here when count == 0.
 *
 * Without this:
 *   Two producers could write the same slot → data corruption.
 *   Consumer could see count > 0 but read a half-written item → torn read.
 *   Missed-signal race: producer posts then consumer tests → infinite sleep.
 *
 * Shutdown: bounded_buffer_begin_shutdown broadcasts both CVs under the lock
 * so every blocked thread wakes, re-evaluates its predicate, and exits.
 * The consumer drains all remaining items before returning, ensuring no
 * log lines are lost when a container exits abruptly.
 */
typedef struct {
    log_item_t      items[LOG_BUFFER_CAPACITY];
    size_t          head, tail, count;
    int             shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty, not_full;
} bounded_buffer_t;

/* Control request: CLI client → supervisor (Path B wire format) */
typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes;
    unsigned long  hard_limit_bytes;
    int            nice_value;
    int            is_run_mode;
} control_request_t;

/* Control response: supervisor → CLI client */
typedef struct {
    int  status;   /* 0=done/ok  1=more-data-follows  2=end-of-stream  <0=error */
    int  container_exit_code;
    char message[MSG_LEN];
} control_response_t;

/* Passed to clone() child */
typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int  nice_value;
    int  pipe_write_fd;
} child_config_t;

/* Passed to each producer thread */
typedef struct {
    int              pipe_read_fd;
    char             container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *log_buffer;
} producer_arg_t;

/* Global supervisor state */
typedef struct {
    int               server_fd, monitor_fd;
    volatile int      should_stop;
    pthread_t         consumer_thread;
    bounded_buffer_t  log_buffer;
    pthread_mutex_t   metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */
static supervisor_ctx_t *g_ctx = NULL;

/* ------------------------------------------------------------------ */
/* Usage                                                                */
/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s supervisor <base-rootfs>\n"
        "  %s start <id> <container-rootfs> <command>"
               " [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s run   <id> <container-rootfs> <command>"
               " [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s ps\n  %s logs <id>\n  %s stop <id>\n",
        prog, prog, prog, prog, prog, prog);
}

/* ------------------------------------------------------------------ */
/* Argument parsing                                                     */
/* ------------------------------------------------------------------ */
static int parse_mib_flag(const char *flag, const char *value,
                           unsigned long *out)
{
    char *end = NULL;
    unsigned long v;
    errno = 0;
    v = strtoul(value, &end, 10);
    if (errno || end == value || *end) {
        fprintf(stderr, "Bad value for %s: %s\n", flag, value); return -1;
    }
    if (v > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Too large for %s\n", flag); return -1;
    }
    *out = v * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req, int argc,
                                 char *argv[], int si)
{
    for (int i = si; i < argc; i += 2) {
        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for %s\n", argv[i]); return -1;
        }
        if (!strcmp(argv[i], "--soft-mib")) {
            if (parse_mib_flag("--soft-mib", argv[i+1], &req->soft_limit_bytes))
                return -1;
        } else if (!strcmp(argv[i], "--hard-mib")) {
            if (parse_mib_flag("--hard-mib", argv[i+1], &req->hard_limit_bytes))
                return -1;
        } else if (!strcmp(argv[i], "--nice")) {
            char *e; long nv = strtol(argv[i+1], &e, 10);
            if (*e || nv < -20 || nv > 19) {
                fprintf(stderr, "Bad --nice (must be -20..19)\n"); return -1;
            }
            req->nice_value = (int)nv;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]); return -1;
        }
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Error: soft limit cannot exceed hard limit\n");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* State helpers                                                        */
/* ------------------------------------------------------------------ */
static const char *state_str(container_state_t s)
{
    switch (s) {
    case CONTAINER_STARTING:    return "starting";
    case CONTAINER_RUNNING:     return "running";
    case CONTAINER_STOPPED:     return "stopped";
    case CONTAINER_HARD_KILLED: return "hard_limit_killed";
    case CONTAINER_KILLED:      return "killed";
    case CONTAINER_EXITED:      return "exited";
    default:                    return "unknown";
    }
}

/* ------------------------------------------------------------------ */
/* Bounded buffer                                                       */
/* ------------------------------------------------------------------ */
static int bb_init(bounded_buffer_t *b)
{
    int rc;
    memset(b, 0, sizeof(*b));
    if ((rc = pthread_mutex_init(&b->mutex, NULL))) return rc;
    if ((rc = pthread_cond_init(&b->not_empty, NULL))) {
        pthread_mutex_destroy(&b->mutex); return rc;
    }
    if ((rc = pthread_cond_init(&b->not_full, NULL))) {
        pthread_cond_destroy(&b->not_empty);
        pthread_mutex_destroy(&b->mutex); return rc;
    }
    return 0;
}

static void bb_destroy(bounded_buffer_t *b)
{
    pthread_cond_destroy(&b->not_full);
    pthread_cond_destroy(&b->not_empty);
    pthread_mutex_destroy(&b->mutex);
}

static void bb_shutdown(bounded_buffer_t *b)
{
    pthread_mutex_lock(&b->mutex);
    b->shutting_down = 1;
    pthread_cond_broadcast(&b->not_empty);
    pthread_cond_broadcast(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
}

/* Returns 0 on success, -1 if shut down and buffer full (drop) */
int bounded_buffer_push(bounded_buffer_t *b, const log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == LOG_BUFFER_CAPACITY && !b->shutting_down)
        pthread_cond_wait(&b->not_full, &b->mutex);
    if (b->shutting_down && b->count == LOG_BUFFER_CAPACITY) {
        pthread_mutex_unlock(&b->mutex); return -1;
    }
    b->items[b->tail] = *item;
    b->tail = (b->tail + 1) % LOG_BUFFER_CAPACITY;
    b->count++;
    pthread_cond_signal(&b->not_empty);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

/* Returns 0 on success, 1 when shutdown + empty (consumer should exit) */
int bounded_buffer_pop(bounded_buffer_t *b, log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == 0 && !b->shutting_down)
        pthread_cond_wait(&b->not_empty, &b->mutex);
    if (b->count == 0) { pthread_mutex_unlock(&b->mutex); return 1; }
    *item = b->items[b->head];
    b->head = (b->head + 1) % LOG_BUFFER_CAPACITY;
    b->count--;
    pthread_cond_signal(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Consumer thread: pop → append to log file                           */
/* ------------------------------------------------------------------ */
void *logging_thread(void *arg)
{
    bounded_buffer_t *buf = (bounded_buffer_t *)arg;
    log_item_t item;
    fprintf(stderr, "[consumer] Logging thread started.\n");
    while (1) {
        if (bounded_buffer_pop(buf, &item) != 0) break;
        char lp[PATH_MAX];
        snprintf(lp, sizeof(lp), "%s/%s.log", LOG_DIR, item.container_id);
        int fd = open(lp, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            const char *ptr = item.data; size_t rem = item.length;
            while (rem > 0) { ssize_t w = write(fd, ptr, rem); if (w<=0) break; ptr+=w; rem-=(size_t)w; }
            close(fd);
        }
    }
    fprintf(stderr, "[consumer] Logging thread exiting — buffer drained.\n");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Producer thread: read pipe → push to buffer                         */
/* ------------------------------------------------------------------ */
static void *producer_thread_fn(void *arg)
{
    producer_arg_t *p = (producer_arg_t *)arg;
    char buf[LOG_CHUNK_SIZE];
    ssize_t n;
    fprintf(stderr, "[producer] Started for container '%s'\n", p->container_id);
    while ((n = read(p->pipe_read_fd, buf, sizeof(buf))) > 0) {
        log_item_t item;
        memset(&item, 0, sizeof(item));
        strncpy(item.container_id, p->container_id, CONTAINER_ID_LEN - 1);
        item.length = (size_t)n;
        memcpy(item.data, buf, (size_t)n);
        bounded_buffer_push(p->log_buffer, &item);
    }
    fprintf(stderr, "[producer] EOF for container '%s', exiting.\n", p->container_id);
    close(p->pipe_read_fd);
    free(p);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Clone child entrypoint                                               */
/* ------------------------------------------------------------------ */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* Redirect stdout + stderr → pipe to supervisor (Path A logging) */
    if (dup2(cfg->pipe_write_fd, STDOUT_FILENO) < 0 ||
        dup2(cfg->pipe_write_fd, STDERR_FILENO) < 0) _exit(1);
    close(cfg->pipe_write_fd);

    /* UTS namespace: each container has its own hostname */
    if (sethostname(cfg->id, strlen(cfg->id)) < 0) { /* non-fatal */ }

    /* Mount namespace + chroot → container sees only its rootfs as / */
    if (chroot(cfg->rootfs) < 0) { perror("chroot"); _exit(1); }
    if (chdir("/") < 0)          { perror("chdir");  _exit(1); }

    /* Mount /proc so tools like ps work inside the container */
    mkdir("/proc", 0755);
    if (mount("proc", "/proc", "proc", 0, NULL) < 0) { /* non-fatal */ }

    /* Task 5: apply nice value for scheduling experiments */
    if (cfg->nice_value != 0)
        setpriority(PRIO_PROCESS, 0, cfg->nice_value);

    /* Execute via /bin/sh -c (handles shell commands and redirection) */
    char *av[] = { "/bin/sh", "-c", cfg->command, NULL };
    execv("/bin/sh", av);
    /* Fallback: direct exec */
    char *av2[] = { cfg->command, NULL };
    execv(cfg->command, av2);
    perror("exec"); _exit(127);
}

/* ------------------------------------------------------------------ */
/* Kernel module helpers                                                */
/* ------------------------------------------------------------------ */
int register_with_monitor(int fd, const char *cid, pid_t pid,
                           unsigned long soft, unsigned long hard)
{
    if (fd < 0) return 0;
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = pid; req.soft_limit_bytes = soft; req.hard_limit_bytes = hard;
    strncpy(req.container_id, cid, sizeof(req.container_id) - 1);
    if (ioctl(fd, MONITOR_REGISTER, &req) < 0) { perror("ioctl REGISTER"); return -1; }
    return 0;
}

int unregister_from_monitor(int fd, const char *cid, pid_t pid)
{
    if (fd < 0) return 0;
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    strncpy(req.container_id, cid, sizeof(req.container_id) - 1);
    ioctl(fd, MONITOR_UNREGISTER, &req);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Metadata helpers (call with metadata_lock held)                     */
/* ------------------------------------------------------------------ */
static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    for (container_record_t *c = ctx->containers; c; c = c->next)
        if (!strcmp(c->id, id)) return c;
    return NULL;
}

static container_record_t *new_container(supervisor_ctx_t *ctx,
                                          const control_request_t *req)
{
    container_record_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    strncpy(c->id, req->container_id, CONTAINER_ID_LEN - 1);
    c->started_at = time(NULL);
    c->state = CONTAINER_STARTING;
    c->soft_limit_bytes = req->soft_limit_bytes;
    c->hard_limit_bytes = req->hard_limit_bytes;
    c->nice_value = req->nice_value;
    c->pipe_read_fd = -1;
    snprintf(c->log_path, sizeof(c->log_path), "%s/%s.log", LOG_DIR, c->id);
    c->next = ctx->containers;
    ctx->containers = c;
    return c;
}

/* ------------------------------------------------------------------ */
/* Launch a container                                                   */
/* ------------------------------------------------------------------ */
static int launch_container(supervisor_ctx_t *ctx, const control_request_t *req,
                             container_record_t *rec)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return -1; }

    child_config_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) { close(pipefd[0]); close(pipefd[1]); return -1; }
    strncpy(cfg->id,      req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(cfg->rootfs,  req->rootfs,       PATH_MAX - 1);
    strncpy(cfg->command, req->command,      CHILD_COMMAND_LEN - 1);
    cfg->nice_value    = req->nice_value;
    cfg->pipe_write_fd = pipefd[1];

    char *stack = malloc(STACK_SIZE);
    if (!stack) { free(cfg); close(pipefd[0]); close(pipefd[1]); return -1; }

    pid_t child = clone(child_fn, stack + STACK_SIZE,
                        CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD, cfg);
    close(pipefd[1]);

    if (child < 0) {
        perror("clone"); free(stack); free(cfg); close(pipefd[0]); return -1;
    }
    /* stack/cfg kept alive until exec() replaces child address space */

    rec->host_pid     = child;
    rec->pipe_read_fd = pipefd[0];
    rec->state        = CONTAINER_RUNNING;

    register_with_monitor(ctx->monitor_fd, rec->id, child,
                          rec->soft_limit_bytes, rec->hard_limit_bytes);

    /* Spin up producer thread for this container */
    producer_arg_t *parg = malloc(sizeof(*parg));
    if (parg) {
        parg->pipe_read_fd = pipefd[0];
        strncpy(parg->container_id, rec->id, CONTAINER_ID_LEN - 1);
        parg->log_buffer = &ctx->log_buffer;
        if (pthread_create(&rec->producer_thread, NULL, producer_thread_fn, parg) == 0)
            rec->producer_started = 1;
        else { free(parg); close(pipefd[0]); }
    }

    fprintf(stderr, "[supervisor] Container '%s' launched (host_pid=%d)\n",
            rec->id, child);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Update container state after child exit — Task 4 attribution rule   */
/* ------------------------------------------------------------------ */
static void apply_exit_status(container_record_t *c, int status)
{
    if (WIFEXITED(status)) {
        c->exit_code   = WEXITSTATUS(status);
        c->exit_signal = 0;
        c->state       = CONTAINER_EXITED;
    } else if (WIFSIGNALED(status)) {
        c->exit_signal = WTERMSIG(status);
        c->exit_code   = 128 + c->exit_signal;
        if (c->stop_requested)
            c->state = CONTAINER_STOPPED;          /* operator stop   */
        else if (c->exit_signal == SIGKILL)
            c->state = CONTAINER_HARD_KILLED;      /* kernel hard limit */
        else
            c->state = CONTAINER_KILLED;           /* unexpected signal */
    }
}

/* ------------------------------------------------------------------ */
/* SIGCHLD: reap zombies, update metadata                              */
/* ------------------------------------------------------------------ */
static void sigchld_handler(int sig)
{
    (void)sig;
    int saved = errno; int status; pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (!g_ctx) continue;
        pthread_mutex_lock(&g_ctx->metadata_lock);
        for (container_record_t *c = g_ctx->containers; c; c = c->next) {
            if (c->host_pid != pid) continue;
            apply_exit_status(c, status);
            unregister_from_monitor(g_ctx->monitor_fd, c->id, pid);
            fprintf(stderr, "[supervisor] '%s' (pid=%d) → %s\n",
                    c->id, pid, state_str(c->state));
            break;
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
    errno = saved;
}

static void sigterm_handler(int sig) { (void)sig; if (g_ctx) g_ctx->should_stop = 1; }

/* ------------------------------------------------------------------ */
/* Send a response struct to the client                                */
/* ------------------------------------------------------------------ */
static void send_resp(int fd, int status, int exit_code, const char *msg)
{
    control_response_t r;
    memset(&r, 0, sizeof(r));
    r.status = status;
    r.container_exit_code = exit_code;
    strncpy(r.message, msg, MSG_LEN - 1);
    send(fd, &r, sizeof(r), 0);
}

/* Send a large string as streaming packets */
static void send_text_stream(int fd, const char *text)
{
    size_t total = strlen(text), sent = 0;
    control_response_t r;
    while (sent < total) {
        size_t chunk = total - sent;
        if (chunk >= MSG_LEN) chunk = MSG_LEN - 1;
        int last = (sent + chunk >= total);
        memset(&r, 0, sizeof(r));
        r.status = last ? 0 : 1;   /* 0=done, 1=more follows */
        memcpy(r.message, text + sent, chunk);
        r.message[chunk] = '\0';
        send(fd, &r, sizeof(r), 0);
        sent += chunk;
    }
}

/* ------------------------------------------------------------------ */
/* Handle one control connection                                       */
/* ------------------------------------------------------------------ */
static void handle_control_request(supervisor_ctx_t *ctx, int cfd)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    ssize_t n = recv(cfd, &req, sizeof(req), MSG_WAITALL);
    if (n != (ssize_t)sizeof(req)) {
        send_resp(cfd, -1, 0, "Partial request"); return;
    }

    switch (req.kind) {

    /* ---- START / RUN ---- */
    case CMD_START:
    case CMD_RUN: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *ex = find_container(ctx, req.container_id);
        if (ex && (ex->state == CONTAINER_STARTING ||
                   ex->state == CONTAINER_RUNNING)) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Container '%s' already running",
                     req.container_id);
            pthread_mutex_unlock(&ctx->metadata_lock);
            send_resp(cfd, -1, 0, msg); break;
        }
        container_record_t *rec = new_container(ctx, &req);
        if (!rec) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            send_resp(cfd, -1, 0, "Out of memory"); break;
        }
        if (launch_container(ctx, &req, rec) < 0) {
            rec->state = CONTAINER_EXITED;
            pthread_mutex_unlock(&ctx->metadata_lock);
            send_resp(cfd, -1, 0, "Launch failed"); break;
        }
        pid_t child_pid = rec->host_pid;
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (req.is_run_mode) {
            char ack[128];
            snprintf(ack, sizeof(ack),
                     "Container '%s' started (pid=%d), waiting...",
                     req.container_id, child_pid);
            send_resp(cfd, 1, 0, ack);  /* streaming: more data follows */

            int ws; pid_t wp;
            do { wp = waitpid(child_pid, &ws, 0); } while (wp < 0 && errno == EINTR);

            pthread_mutex_lock(&ctx->metadata_lock);
            container_record_t *r = find_container(ctx, req.container_id);
            int ec = 0;
            if (r) {
                apply_exit_status(r, ws);
                unregister_from_monitor(ctx->monitor_fd, r->id, child_pid);
                ec = r->exit_code;
                fprintf(stderr, "[supervisor] '%s' (pid=%d) → %s (run mode)\n",
                        r->id, child_pid, state_str(r->state));
            }
            pthread_mutex_unlock(&ctx->metadata_lock);

            char done[128];
            snprintf(done, sizeof(done), "Container '%s' exited (code=%d)",
                     req.container_id, ec);
            send_resp(cfd, 0, ec, done);
        } else {
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "Container '%s' started in background (pid=%d)",
                     req.container_id, child_pid);
            send_resp(cfd, 0, 0, msg);
        }
        break;
    }

    /* ---- PS ---- */
    case CMD_PS: {
        /* Build table in a heap buffer then stream it */
        size_t bufsz = 16384;
        char *buf = calloc(1, bufsz);
        if (!buf) { send_resp(cfd, -1, 0, "OOM"); break; }
        int off = 0;
        off += snprintf(buf+off, bufsz-(size_t)off,
            "%-16s %-8s %-18s %-10s %-10s %-5s  %s\n",
            "CONTAINER_ID","PID","STATE","SOFT_MiB","HARD_MiB","NICE","STARTED");
        off += snprintf(buf+off, bufsz-(size_t)off,
            "%-16s %-8s %-18s %-10s %-10s %-5s  %s\n",
            "----------------","--------","------------------",
            "----------","----------","-----","--------");

        pthread_mutex_lock(&ctx->metadata_lock);
        for (container_record_t *c = ctx->containers; c; c = c->next) {
            char ts[16];
            struct tm *ti = localtime(&c->started_at);
            strftime(ts, sizeof(ts), "%H:%M:%S", ti);
            off += snprintf(buf+off, bufsz-(size_t)off,
                "%-16s %-8d %-18s %-10lu %-10lu %-5d  %s",
                c->id, c->host_pid, state_str(c->state),
                c->soft_limit_bytes>>20, c->hard_limit_bytes>>20,
                c->nice_value, ts);
            if (c->state == CONTAINER_EXITED)
                off += snprintf(buf+off, bufsz-(size_t)off, "  (exit=%d)", c->exit_code);
            else if (c->state != CONTAINER_RUNNING && c->state != CONTAINER_STARTING)
                off += snprintf(buf+off, bufsz-(size_t)off, "  (sig=%d)", c->exit_signal);
            off += snprintf(buf+off, bufsz-(size_t)off, "\n");
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (off <= 0) snprintf(buf, bufsz, "(no containers tracked)\n");
        send_text_stream(cfd, buf);
        free(buf);
        break;
    }

    /* ---- LOGS ---- */
    case CMD_LOGS: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = find_container(ctx, req.container_id);
        char lp[PATH_MAX] = {0};
        if (c) strncpy(lp, c->log_path, PATH_MAX - 1);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!lp[0]) {
            char msg[64]; snprintf(msg, sizeof(msg), "No container '%s'", req.container_id);
            send_resp(cfd, -1, 0, msg); break;
        }

        /* Header */
        char hdr[MSG_LEN]; snprintf(hdr, sizeof(hdr), "=== Log: %s ===\n", lp);
        send_resp(cfd, 1, 0, hdr);

        int lfd = open(lp, O_RDONLY);
        if (lfd >= 0) {
            char chunk[LOG_CHUNK_SIZE]; ssize_t r;
            while ((r = read(lfd, chunk, sizeof(chunk) - 1)) > 0) {
                chunk[r] = '\0';
                send_resp(cfd, 1, 0, chunk);
            }
            close(lfd);
        } else {
            send_resp(cfd, 1, 0, "(log file not yet created)\n");
        }
        send_resp(cfd, 2, 0, "=== End of log ===\n");
        break;
    }

    /* ---- STOP ---- */
    case CMD_STOP: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = find_container(ctx, req.container_id);
        if (!c) {
            char msg[64]; snprintf(msg, sizeof(msg), "No container '%s'", req.container_id);
            pthread_mutex_unlock(&ctx->metadata_lock);
            send_resp(cfd, -1, 0, msg); break;
        }
        if (c->state != CONTAINER_RUNNING && c->state != CONTAINER_STARTING) {
            char msg[128]; snprintf(msg, sizeof(msg),
                "Container '%s' not running (state=%s)",
                req.container_id, state_str(c->state));
            pthread_mutex_unlock(&ctx->metadata_lock);
            send_resp(cfd, -1, 0, msg); break;
        }
        /* Set stop_requested BEFORE sending any signal (Task 4 attribution) */
        c->stop_requested = 1;
        pid_t pid = c->host_pid;
        pthread_mutex_unlock(&ctx->metadata_lock);

        kill(pid, SIGTERM);
        usleep(500000);
        if (kill(pid, 0) == 0) kill(pid, SIGKILL);

        char msg[128];
        snprintf(msg, sizeof(msg), "Stop sent to '%s' (pid=%d)", req.container_id, pid);
        send_resp(cfd, 0, 0, msg);
        break;
    }

    default:
        send_resp(cfd, -1, 0, "Unknown command");
    }
}

/* ------------------------------------------------------------------ */
/* Supervisor main loop                                                 */
/* ------------------------------------------------------------------ */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = ctx.monitor_fd = -1;
    g_ctx = &ctx;

    mkdir(LOG_DIR, 0755);
    pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (bb_init(&ctx.log_buffer) != 0) { perror("bb_init"); return 1; }

    ctx.monitor_fd = open(MONITOR_DEVICE, O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "[supervisor] Warning: %s unavailable (%s). "
                "Memory monitoring disabled.\n", MONITOR_DEVICE, strerror(errno));
    else
        fprintf(stderr, "[supervisor] Kernel monitor opened: %s\n", MONITOR_DEVICE);

    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);
    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(ctx.server_fd, 16) < 0) { perror("listen"); return 1; }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_handler = sigterm_handler; sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (pthread_create(&ctx.consumer_thread, NULL, logging_thread, &ctx.log_buffer)) {
        perror("pthread_create consumer"); return 1;
    }

    int fl = fcntl(ctx.server_fd, F_GETFL, 0);
    fcntl(ctx.server_fd, F_SETFL, fl | O_NONBLOCK);

    fprintf(stderr, "[supervisor] Ready. rootfs=%s  socket=%s\n",
            rootfs, CONTROL_PATH);

    while (!ctx.should_stop) {
        int cfd = accept(ctx.server_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                usleep(50000); continue;
            }
            if (!ctx.should_stop) perror("accept");
            break;
        }
        handle_control_request(&ctx, cfd);
        close(cfd);
    }

    fprintf(stderr, "[supervisor] Shutting down...\n");
    pthread_mutex_lock(&ctx.metadata_lock);
    for (container_record_t *c = ctx.containers; c; c = c->next)
        if (c->state == CONTAINER_RUNNING || c->state == CONTAINER_STARTING) {
            c->stop_requested = 1; kill(c->host_pid, SIGTERM);
        }
    pthread_mutex_unlock(&ctx.metadata_lock);
    usleep(600000);
    pthread_mutex_lock(&ctx.metadata_lock);
    for (container_record_t *c = ctx.containers; c; c = c->next)
        if (c->state == CONTAINER_RUNNING || c->state == CONTAINER_STARTING)
            kill(c->host_pid, SIGKILL);
    pthread_mutex_unlock(&ctx.metadata_lock);
    while (waitpid(-1, NULL, WNOHANG) > 0); sleep(1); while (waitpid(-1, NULL, WNOHANG) > 0);

    pthread_mutex_lock(&ctx.metadata_lock);
    for (container_record_t *c = ctx.containers; c; c = c->next)
        if (c->producer_started) {
            pthread_join(c->producer_thread, NULL);
            c->producer_started = 0;
            fprintf(stderr, "[supervisor] Producer '%s' joined.\n", c->id);
        }
    pthread_mutex_unlock(&ctx.metadata_lock);

    bb_shutdown(&ctx.log_buffer);
    pthread_join(ctx.consumer_thread, NULL);
    fprintf(stderr, "[supervisor] Consumer joined.\n");

    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *c = ctx.containers, *nx;
    while (c) { nx = c->next; free(c); c = nx; }
    ctx.containers = NULL;
    pthread_mutex_unlock(&ctx.metadata_lock);

    bb_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    close(ctx.server_fd); unlink(CONTROL_PATH);
    fprintf(stderr, "[supervisor] Clean shutdown complete.\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Client-side signal forwarding for `engine run`                      */
/* ------------------------------------------------------------------ */
static int      g_run_sock = -1;
static char     g_run_id[CONTAINER_ID_LEN];

static void run_sig_fwd(int sig)
{
    (void)sig;
    if (g_run_sock < 0) return;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_un a; memset(&a,0,sizeof(a));
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, CONTROL_PATH, sizeof(a.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&a, sizeof(a)) == 0) {
        control_request_t req; memset(&req,0,sizeof(req));
        req.kind = CMD_STOP;
        strncpy(req.container_id, g_run_id, CONTAINER_ID_LEN-1);
        send(fd, &req, sizeof(req), 0);
        control_response_t dummy; recv(fd, &dummy, sizeof(dummy), 0);
    }
    close(fd); g_run_sock = -1;
}

/* ------------------------------------------------------------------ */
/* Client: send request, print responses                               */
/* ------------------------------------------------------------------ */
static int send_control_request(const control_request_t *req)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to supervisor at %s: %s\n"
                "Is the supervisor running? (sudo ./engine supervisor <rootfs>)\n",
                CONTROL_PATH, strerror(errno));
        close(fd); return 1;
    }

    if (req->is_run_mode) {
        g_run_sock = fd;
        strncpy(g_run_id, req->container_id, CONTAINER_ID_LEN-1);
        struct sigaction sa; memset(&sa,0,sizeof(sa));
        sa.sa_handler = run_sig_fwd; sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    }

    if (send(fd, req, sizeof(*req), 0) != (ssize_t)sizeof(*req)) {
        perror("send"); close(fd); return 1;
    }

    control_response_t resp; int done = 0, ret = 0;
    while (!done) {
        ssize_t n = recv(fd, &resp, sizeof(resp), MSG_WAITALL);
        if (n != (ssize_t)sizeof(resp)) break;
        switch (resp.status) {
        case 0: printf("%s\n", resp.message); fflush(stdout); done = 1; break;
        case 1: printf("%s", resp.message);   fflush(stdout); break;
        case 2: printf("%s\n", resp.message); fflush(stdout); done = 1; break;
        default: fprintf(stderr, "Error: %s\n", resp.message); ret=1; done=1; break;
        }
    }
    close(fd); g_run_sock = -1;
    return ret;
}

/* ------------------------------------------------------------------ */
/* CLI commands                                                         */
/* ------------------------------------------------------------------ */
static int cmd_start(int argc, char *argv[])
{
    if (argc < 5) { usage(argv[0]); return 1; }
    control_request_t req; memset(&req,0,sizeof(req));
    req.kind=CMD_START; req.soft_limit_bytes=DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes=DEFAULT_HARD_LIMIT;
    strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1);
    strncpy(req.rootfs,argv[3],PATH_MAX-1);
    strncpy(req.command,argv[4],CHILD_COMMAND_LEN-1);
    if (parse_optional_flags(&req,argc,argv,5)) return 1;
    return send_control_request(&req);
}
static int cmd_run(int argc, char *argv[])
{
    if (argc < 5) { usage(argv[0]); return 1; }
    control_request_t req; memset(&req,0,sizeof(req));
    req.kind=CMD_RUN; req.is_run_mode=1;
    req.soft_limit_bytes=DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes=DEFAULT_HARD_LIMIT;
    strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1);
    strncpy(req.rootfs,argv[3],PATH_MAX-1);
    strncpy(req.command,argv[4],CHILD_COMMAND_LEN-1);
    if (parse_optional_flags(&req,argc,argv,5)) return 1;
    return send_control_request(&req);
}
static int cmd_ps(void)
{
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_PS;
    return send_control_request(&req);
}
static int cmd_logs(int argc, char *argv[])
{
    if (argc < 3) { fprintf(stderr,"Usage: %s logs <id>\n",argv[0]); return 1; }
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_LOGS;
    strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1);
    return send_control_request(&req);
}
static int cmd_stop(int argc, char *argv[])
{
    if (argc < 3) { fprintf(stderr,"Usage: %s stop <id>\n",argv[0]); return 1; }
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_STOP;
    strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1);
    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }
    if (!strcmp(argv[1],"supervisor")) {
        if (argc<3) { fprintf(stderr,"Usage: %s supervisor <rootfs>\n",argv[0]); return 1; }
        return run_supervisor(argv[2]);
    }
    if (!strcmp(argv[1],"start")) return cmd_start(argc,argv);
    if (!strcmp(argv[1],"run"))   return cmd_run(argc,argv);
    if (!strcmp(argv[1],"ps"))    return cmd_ps();
    if (!strcmp(argv[1],"logs"))  return cmd_logs(argc,argv);
    if (!strcmp(argv[1],"stop"))  return cmd_stop(argc,argv);
    usage(argv[0]); return 1;
}
