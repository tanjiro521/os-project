/*
 * proc_monitor.c - a small top-like process monitor for Linux.
 *
 * Build: gcc -O2 -Wall -Wextra -o proc_monitor proc_monitor.c
 * Run:   ./proc_monitor
 * Keys:  c = sort by CPU, m = sort by memory, p = sort by PID, q = quit
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define REFRESH_SECONDS 1.0
#define HEADER_LINES    4
#define PREFIX_WIDTH    48   /* width of all columns before COMMAND */

typedef enum { SORT_CPU, SORT_MEM, SORT_PID } SortMode;

typedef struct {
    int pid;
    uid_t uid;
    char name[64];
    char state;
    unsigned long long cpu_ticks;
    unsigned long long rss_kb;
    unsigned long long virt_kb;
    double cpu_percent;
} Process;

typedef struct {
    int pid;
    unsigned long long ticks;
} PrevEntry;

/* ---------- global state ---------- */
static long page_kb = 4;
static long clock_ticks = 100;
static int cpu_count = 1;

static Process *items = NULL;
static size_t item_count = 0, item_cap = 0;

static PrevEntry *prev = NULL;
static size_t prev_count = 0, prev_cap = 0;
static unsigned long long last_total_ticks = 0;

static SortMode mode = SORT_CPU;

static struct termios original_terminal;
static int terminal_changed = 0;
static int interactive = 0;

static volatile sig_atomic_t stop_flag = 0;
static volatile sig_atomic_t resized = 0;

/* ---------- small helpers ---------- */

static int read_file(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void format_time(double seconds, char *buffer, size_t size) {
    long total = (long)seconds;
    long days = total / 86400; total %= 86400;
    long hours = total / 3600; total %= 3600;
    long minutes = total / 60; total %= 60;
    if (days) snprintf(buffer, size, "%ldd %02ld:%02ld:%02ld", days, hours, minutes, total);
    else      snprintf(buffer, size, "%02ld:%02ld:%02ld", hours, minutes, total);
}

/* Cached uid -> user name lookup. */
static const char *user_name(uid_t uid) {
    enum { CACHE_SIZE = 256 };
    static struct { uid_t uid; char name[32]; } cache[CACHE_SIZE];
    static size_t used = 0;
    static char fallback[32];

    for (size_t i = 0; i < used; ++i)
        if (cache[i].uid == uid) return cache[i].name;

    struct passwd *pw = getpwuid(uid);
    if (used < CACHE_SIZE) {
        cache[used].uid = uid;
        if (pw) snprintf(cache[used].name, sizeof cache[used].name, "%s", pw->pw_name);
        else    snprintf(cache[used].name, sizeof cache[used].name, "%u", (unsigned)uid);
        return cache[used++].name;
    }
    if (pw) snprintf(fallback, sizeof fallback, "%s", pw->pw_name);
    else    snprintf(fallback, sizeof fallback, "%u", (unsigned)uid);
    return fallback;
}

/* ---------- system information ---------- */

static unsigned long long read_total_cpu_ticks(void) {
    char buf[512];
    unsigned long long v[8] = {0};
    if (read_file("/proc/stat", buf, sizeof buf) <= 0) return 0;
    if (sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) < 4)
        return 0;
    unsigned long long total = 0;
    for (int i = 0; i < 8; ++i) total += v[i];
    return total;
}

static void read_memory(long long *total_mb, long long *used_mb,
                        long long *swap_total_mb, long long *swap_used_mb) {
    char line[256], name[64];
    long long value, mem_total = 0, mem_avail = 0, swap_total = 0, swap_free = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        while (fgets(line, sizeof line, f)) {
            if (sscanf(line, "%63s %lld", name, &value) != 2) continue;
            if      (!strcmp(name, "MemTotal:"))     mem_total  = value;
            else if (!strcmp(name, "MemAvailable:")) mem_avail  = value;
            else if (!strcmp(name, "SwapTotal:"))    swap_total = value;
            else if (!strcmp(name, "SwapFree:"))     swap_free  = value;
        }
        fclose(f);
    }
    *total_mb      = mem_total / 1024;
    *used_mb       = (mem_total - mem_avail) / 1024;
    *swap_total_mb = swap_total / 1024;
    *swap_used_mb  = (swap_total - swap_free) / 1024;
}

static double read_uptime(void) {
    char buf[128];
    double up = 0;
    if (read_file("/proc/uptime", buf, sizeof buf) > 0) sscanf(buf, "%lf", &up);
    return up;
}

static void read_loadavg(double load[3]) {
    char buf[128];
    load[0] = load[1] = load[2] = 0;
    if (read_file("/proc/loadavg", buf, sizeof buf) > 0)
        sscanf(buf, "%lf %lf %lf", &load[0], &load[1], &load[2]);
}

/* ---------- process scanning ---------- */

static int read_process(int pid, Process *p) {
    char path[64], buf[1024];
    struct stat st;

    memset(p, 0, sizeof *p);
    p->pid = pid;

    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    if (read_file(path, buf, sizeof buf) <= 0) return 0;

    /* The command name is in parentheses and may itself contain ')' or spaces. */
    char *lparen = strchr(buf, '(');
    char *rparen = strrchr(buf, ')');
    if (!lparen || !rparen || rparen < lparen) return 0;

    size_t len = (size_t)(rparen - lparen - 1);
    if (len >= sizeof p->name) len = sizeof p->name - 1;
    memcpy(p->name, lparen + 1, len);
    p->name[len] = '\0';

    unsigned long long utime, stime, vsize;
    long long rss_pages;
    if (sscanf(rparen + 2,
               "%c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu "
               "%*d %*d %*d %*d %*d %*d %*u %llu %lld",
               &p->state, &utime, &stime, &vsize, &rss_pages) != 5)
        return 0;

    p->cpu_ticks = utime + stime;
    p->virt_kb = vsize / 1024ULL;
    p->rss_kb = rss_pages > 0 ? (unsigned long long)rss_pages * (unsigned long long)page_kb : 0;

    snprintf(path, sizeof path, "/proc/%d", pid);
    p->uid = stat(path, &st) == 0 ? st.st_uid : (uid_t)-1;
    return 1;
}

static int compare_pid(const void *a, const void *b) {
    const Process *x = a, *y = b;
    return (x->pid > y->pid) - (x->pid < y->pid);
}

static int compare_cpu(const void *a, const void *b) {
    const Process *x = a, *y = b;
    if (x->cpu_percent < y->cpu_percent) return 1;
    if (x->cpu_percent > y->cpu_percent) return -1;
    return compare_pid(a, b);
}

static int compare_memory(const void *a, const void *b) {
    const Process *x = a, *y = b;
    if (x->rss_kb < y->rss_kb) return 1;
    if (x->rss_kb > y->rss_kb) return -1;
    return compare_pid(a, b);
}

static int compare_prev(const void *a, const void *b) {
    const PrevEntry *x = a, *y = b;
    return (x->pid > y->pid) - (x->pid < y->pid);
}

static void sort_items(void) {
    int (*cmp)(const void *, const void *) =
        mode == SORT_CPU ? compare_cpu : mode == SORT_MEM ? compare_memory : compare_pid;
    qsort(items, item_count, sizeof *items, cmp);
}

/* Reads every process, computes CPU% from the change since the last scan. */
static int refresh_processes(void) {
    DIR *dir = opendir("/proc");
    if (!dir) return 0;

    item_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;

        if (item_count == item_cap) {
            size_t new_cap = item_cap ? item_cap * 2 : 256;
            Process *grown = realloc(items, new_cap * sizeof *items);
            if (!grown) break;
            items = grown;
            item_cap = new_cap;
        }
        if (read_process(atoi(entry->d_name), &items[item_count])) ++item_count;
    }
    closedir(dir);

    unsigned long long total = read_total_cpu_ticks();
    unsigned long long total_delta = total > last_total_ticks ? total - last_total_ticks : 0;
    last_total_ticks = total;

    /* Sorting by PID lets us binary-search the previous scan. */
    qsort(items, item_count, sizeof *items, compare_pid);

    for (size_t i = 0; i < item_count; ++i) {
        PrevEntry key = { items[i].pid, 0 };
        PrevEntry *old = prev_count ? bsearch(&key, prev, prev_count, sizeof *prev, compare_prev) : NULL;
        if (old && total_delta && items[i].cpu_ticks >= old->ticks)
            items[i].cpu_percent = 100.0 * (double)(items[i].cpu_ticks - old->ticks)
                                 * (double)cpu_count / (double)total_delta;
    }

    /* Remember this scan (still sorted by PID) for the next refresh. */
    if (item_count > prev_cap) {
        PrevEntry *grown = realloc(prev, item_count * sizeof *prev);
        if (grown) { prev = grown; prev_cap = item_count; }
    }
    prev_count = item_count <= prev_cap ? item_count : 0;
    for (size_t i = 0; i < prev_count; ++i) {
        prev[i].pid = items[i].pid;
        prev[i].ticks = items[i].cpu_ticks;
    }

    sort_items();
    return 1;
}

/* ---------- drawing ---------- */

static void draw_screen(void) {
    struct winsize ws;
    int rows = 24, cols = 80;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0) {
        rows = ws.ws_row;
        cols = ws.ws_col;
    }

    char up[64];
    double load[3];
    long long mem_total, mem_used, swap_total, swap_used;
    format_time(read_uptime(), up, sizeof up);
    read_loadavg(load);
    read_memory(&mem_total, &mem_used, &swap_total, &swap_used);

    int cmd_width = cols - PREFIX_WIDTH;
    if (cmd_width < 10) cmd_width = 10;
    size_t max_rows = rows > HEADER_LINES + 1 ? (size_t)(rows - HEADER_LINES - 1) : 1;
    size_t shown = item_count < max_rows ? item_count : max_rows;

    printf("\033[H");
    printf("PROC MONITOR  Uptime: %s  Load: %.2f %.2f %.2f  Tasks: %zu  CPUs: %d\033[K\n",
           up, load[0], load[1], load[2], item_count, cpu_count);
    printf("Mem: %lld/%lld MiB  Swap: %lld/%lld MiB  Sort: %s\033[K\n",
           mem_used, mem_total, swap_used, swap_total,
           mode == SORT_CPU ? "CPU" : mode == SORT_MEM ? "MEMORY" : "PID");
    printf("Keys: [c] CPU  [m] memory  [p] PID  [q] quit\033[K\n");
    printf("\033[7m%-7s %-10s %c %6s %9s %9s COMMAND\033[K\033[0m\n",
           "PID", "USER", 'S', "CPU%", "RES(MB)", "VIRT(MB)");

    for (size_t i = 0; i < shown; ++i) {
        const Process *p = &items[i];
        printf("%-7d %-10.10s %c %6.1f %9.1f %9.1f %.*s\033[K\n",
               p->pid, user_name(p->uid), p->state, p->cpu_percent,
               (double)p->rss_kb / 1024.0, (double)p->virt_kb / 1024.0,
               cmd_width, p->name);
    }
    printf("\033[J");
    fflush(stdout);
}

/* ---------- terminal and signals ---------- */

static void handle_signal(int sig) {
    if (sig == SIGWINCH) resized = 1;
    else stop_flag = 1;
}

static void restore_terminal(void) {
    if (terminal_changed) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_terminal);
        terminal_changed = 0;
    }
    printf("\033[?25h\033[?1049l");
    fflush(stdout);
}

static void setup_terminal(void) {
    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original_terminal) == 0) {
        struct termios raw = original_terminal;
        raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0) {
            terminal_changed = 1;
            interactive = 1;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);          /* no SA_RESTART: select() must wake up */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGWINCH, &sa, NULL);

    atexit(restore_terminal);
    printf("\033[?1049h\033[?25l");     /* alternate screen, hide cursor */
    fflush(stdout);
}

/* Waits up to 'ms' milliseconds; returns a key, or 0 on timeout/interrupt. */
static int wait_key(int ms) {
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    fd_set set;
    FD_ZERO(&set);
    if (interactive) FD_SET(STDIN_FILENO, &set);

    int ready = select(interactive ? STDIN_FILENO + 1 : 0,
                       interactive ? &set : NULL, NULL, NULL, &tv);
    if (ready <= 0) return 0;

    char key;
    ssize_t n = read(STDIN_FILENO, &key, 1);
    if (n == 1) return (unsigned char)key;
    if (n == 0) interactive = 0;        /* stdin closed: just keep refreshing */
    return 0;
}

/* ---------- main ---------- */

int main(void) {
    long v = sysconf(_SC_PAGESIZE);
    if (v > 0) page_kb = v / 1024;
    v = sysconf(_SC_CLK_TCK);
    if (v > 0) clock_ticks = v;
    v = sysconf(_SC_NPROCESSORS_ONLN);
    if (v > 0) cpu_count = (int)v;
    (void)clock_ticks;

    static char out_buffer[1 << 16];
    setvbuf(stdout, out_buffer, _IOFBF, sizeof out_buffer);

    setup_terminal();

    /* Take a baseline scan so the first screen already shows real CPU%. */
    last_total_ticks = read_total_cpu_ticks();
    if (!refresh_processes()) {
        restore_terminal();
        perror("Unable to read /proc");
        return 1;
    }
    wait_key(250);

    while (!stop_flag) {
        if (!refresh_processes()) break;
        draw_screen();

        double deadline = now_seconds() + REFRESH_SECONDS;
        while (!stop_flag) {
            double left = deadline - now_seconds();
            if (left <= 0) break;

            int key = wait_key((int)(left * 1000.0) + 1);
            int redraw = 0;

            switch (tolower(key)) {
            case 'q': stop_flag = 1; break;
            case 'c': mode = SORT_CPU;  redraw = 1; break;
            case 'm': mode = SORT_MEM;  redraw = 1; break;
            case 'p': mode = SORT_PID;  redraw = 1; break;
            default: break;
            }
            if (resized) { resized = 0; redraw = 1; }
            if (redraw && !stop_flag) {
                sort_items();
                draw_screen();
            }
        }
    }

    free(items);
    free(prev);
    return 0;      /* terminal is restored by the atexit handler */
}
