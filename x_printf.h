#pragma once

#if defined(__linux__)
        #ifndef _GNU_SOURCE
                #define _GNU_SOURCE
        #endif
#endif

#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>

/* Platform-specific includes for syscall */
#if defined(__linux__)
        #include <sys/syscall.h>
#endif

/* Define LOCAL to avoid variable name conflicts in macros */
#define LOCAL(x) __##x

/*
 * Get program name for log file path
 */
#if defined(__linux__) && defined(_GNU_SOURCE)
        #define LOG_PROG_NAME ({ \
                const char *LOCAL(name) = program_invocation_short_name; \
                LOCAL(name) ? LOCAL(name) : "app"; \
        })
#elif defined(__APPLE__) || defined(__FreeBSD__)
        #define LOG_PROG_NAME ({ \
                const char *LOCAL(name) = getprogname(); \
                LOCAL(name) ? LOCAL(name) : "app"; \
        })
#else
        #define LOG_PROG_NAME "app"
#endif

/*
 * Log level display names (without padding for flexibility)
 */
#define LOG_DEBUG_NAME    "DEBUG"
#define LOG_INFO_NAME     "INFO"
#define LOG_NOTICE_NAME   "NOTICE"
#define LOG_WARNING_NAME  "WARN"
#define LOG_ERR_NAME      "ERROR"
#define LOG_CRIT_NAME     "CRIT"
#define LOG_EMERG_NAME    "SYS"
#define LOG_ALERT_NAME    "FATAL"

/*
 * Map syslog level macros to log level names
 */
#define LOG_LEVEL_NAME(level) \
        ((level) == LOG_DEBUG ? LOG_DEBUG_NAME : \
         (level) == LOG_INFO ? LOG_INFO_NAME : \
         (level) == LOG_NOTICE ? LOG_NOTICE_NAME : \
         (level) == LOG_WARNING ? LOG_WARNING_NAME : \
         (level) == LOG_ERR ? LOG_ERR_NAME : \
         (level) == LOG_CRIT ? LOG_CRIT_NAME : \
         (level) == LOG_EMERG ? LOG_EMERG_NAME : \
         (level) == LOG_ALERT ? LOG_ALERT_NAME : "UNKNOWN")

/* Thread ID portability */
#ifndef gettid
        #if defined(__linux__)
                #define gettid() syscall(SYS_gettid)
        #elif defined(__APPLE__)
                #define gettid() syscall(SYS_thread_selfid)
        #else
                #define gettid() ((unsigned long)pthread_self())
        #endif
#endif

/*
 * Extract basename of file for concise logging
 */
#define __FILENAME__ ({ \
        const char *LOCAL(p) = strrchr(__FILE__, '/'); \
        LOCAL(p) ? LOCAL(p) + 1 : __FILE__; \
})

/*
 * Define default log file path
 * Default: /var/log/<program_name>.log
 */
#ifndef DEFAULT_LOG_FILE_PATH
        #define DEFAULT_LOG_FILE_PATH ({ \
                static char LOCAL(buf)[256]; \
                snprintf(LOCAL(buf), sizeof(LOCAL(buf)), "/var/log/%s.log", LOG_PROG_NAME); \
                LOCAL(buf); \
        })
#endif

/*
 * Global log file handle and path
 */
static FILE *g_log_file = NULL;
static pthread_once_t g_log_file_once = PTHREAD_ONCE_INIT;
static char g_log_file_path[256] = {0};

/*
 * Global log destination control (false for stdout, true for file)
 */
static bool g_log_to_file = true; /* Default to file logging */

/*
 * Global log level threshold (default to LOG_DEBUG to allow all levels)
 */
static int g_log_level_threshold = LOG_DEBUG;

/*
 * Initialize log file handle, open g_log_file_path or DEFAULT_LOG_FILE_PATH
 */
static void init_log_file(void) {
        const char *path = g_log_file_path[0] ? g_log_file_path : DEFAULT_LOG_FILE_PATH;
        int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0666);
        if (fd >= 0) {
                g_log_file = fdopen(fd, "a");
                if (g_log_file == NULL) {
                        close(fd);
                        perror("g_log_file_get: fdopen failed");
                }
        } else {
                perror("g_log_file_get: open failed");
        }
}

/*
 * Get log file handle, open g_log_file_path or DEFAULT_LOG_FILE_PATH if not already open
 * Returns stdout on failure
 */
static inline FILE *g_log_file_get(void) {
        pthread_once(&g_log_file_once, init_log_file);
        return g_log_file ? g_log_file : stdout;
}

/* ========================================================================= */
/*                           Callable Macros Below                            */
/* ========================================================================= */

/*
 * Set the log file path and reinitialize the log file handle
 */
#define x_set_log_path(path) do { \
        strncpy(g_log_file_path, (path), sizeof(g_log_file_path) - 1); \
        g_log_file_path[sizeof(g_log_file_path) - 1] = '\0'; \
        if (g_log_file) { \
                fclose(g_log_file); \
                g_log_file = NULL; \
        } \
        g_log_file_once = PTHREAD_ONCE_INIT; \
        g_log_file_get(); \
} while (0)

/*
 * Set the log destination (false for stdout, true for file)
 */
#define x_set_log_to_file(to_file) do { \
        g_log_to_file = (to_file); \
} while (0)

/*
 * Set the minimum log level for output
 */
#define x_set_log_level(level) do { \
        g_log_level_threshold = (level); \
} while (0)

/*
 * Terminal/file log format macro
 * Format: LEVEL | thread_id | filename:line | function() | message
 * Writes to g_log_file_path or DEFAULT_LOG_FILE_PATH with O_APPEND (atomic writes, no locking needed) if g_log_to_file is true
 * Writes to stdout (no locking, assumes low contention or single-threaded) if g_log_to_file is false
 * Only logs if level is greater than or equal to the global threshold
 */
#define x_printf(level, fmt, ...) do { \
        if ((level) <= g_log_level_threshold) { \
                FILE *LOCAL(stream) = g_log_to_file ? g_log_file_get() : stdout; \
                int LOCAL(ret) = fprintf(LOCAL(stream), "%-6s|%06ld|%s:%d|%s()|" fmt "\n", \
                                         LOG_LEVEL_NAME(level), (long)gettid(), __FILENAME__, __LINE__, \
                                         __FUNCTION__, ##__VA_ARGS__); \
                if (LOCAL(ret) >= 0) { \
                        fflush(LOCAL(stream)); \
                } else { \
                        perror("x_printf: fprintf failed"); \
                } \
        } \
} while (0)

/*
 * Log level macros using syslog level names
 */
#define x_pdebug(...)   x_printf(LOG_DEBUG, ##__VA_ARGS__)
#define x_pinfo(...)    x_printf(LOG_INFO, ##__VA_ARGS__)
#define x_pnotice(...)  x_printf(LOG_NOTICE, ##__VA_ARGS__)
#define x_pwarn(...)    x_printf(LOG_WARNING, ##__VA_ARGS__)
#define x_perror(...)   x_printf(LOG_ERR, ##__VA_ARGS__)
#define x_pcrit(...)    x_printf(LOG_CRIT, ##__VA_ARGS__)
#define x_psys(...)     x_printf(LOG_EMERG, ##__VA_ARGS__)
#define x_pfatal(...)   x_printf(LOG_ALERT, ##__VA_ARGS__)
