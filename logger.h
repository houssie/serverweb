#ifndef LOGGER_H
#define LOGGER_H

#include "config.h"

void init_logger(const char *log_file);
void log_message(LogLevel level, const char *format, ...);
void close_logger();

#endif