#include "logger.h"
#include <stdarg.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

static FILE *log_file = NULL;
static LogLevel current_level = LOG_DEBUG;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_logger(const char *filename) {
    if (filename) {
        log_file = fopen(filename, "a");
        if (!log_file) {
            fprintf(stderr, "Cannot open log file: %s\n", filename);
            log_file = stdout;
        }
    } else {
        log_file = stdout;
    }
}

void log_message(LogLevel level, const char *format, ...) {
    if (level < current_level) return;
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    
    char time_buffer[26];
    strftime(time_buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    const char *level_str;
    switch(level) {
        case LOG_DEBUG: level_str = "DEBUG"; break;
        case LOG_INFO: level_str = "INFO"; break;
        case LOG_WARNING: level_str = "WARN"; break;
        case LOG_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }
    
    pthread_mutex_lock(&log_mutex);
    fprintf(log_file, "[%s.%.3d] [%s] ", time_buffer, (int)(tv.tv_usec / 1000), level_str);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
}

void close_logger() {
    if (log_file && log_file != stdout) {
        fclose(log_file);
    }
}