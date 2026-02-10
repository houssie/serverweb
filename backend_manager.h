#ifndef BACKEND_MANAGER_H
#define BACKEND_MANAGER_H

#include "config.h"

Backend* load_backends(const char *filename, int *count);
void free_backends(Backend *backends, int count);
void increment_backend_connections(Backend *backend);
void decrement_backend_connections(Backend *backend);
void update_backend_health(Backend *backend, int is_healthy);
void* health_check_thread(void *arg);
int get_total_backends_weight(Backend *backends, int count);
void print_backend_stats(Backend *backends, int count);

#endif