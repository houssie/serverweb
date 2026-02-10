#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "config.h"

Backend* select_backend(Backend *backends, int count, LBStrategy strategy, const char *client_ip);
void print_load_balancing_stats(Backend *backends, int count);
void reset_backend_stats(Backend *backends, int count);

#endif