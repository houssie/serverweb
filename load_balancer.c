#include "load_balancer.h"
#include "utils.h"
#include "backend_manager.h"
#include <limits.h>
#include <string.h>

static int round_robin_index = 0;
static pthread_mutex_t rr_mutex = PTHREAD_MUTEX_INITIALIZER;

Backend* select_backend(Backend *backends, int count, LBStrategy strategy, const char *client_ip) {
    if (count == 0) return NULL;
    
    Backend *healthy[MAX_BACKENDS];
    int healthy_count = 0;
    
    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&backends[i].lock);
        if (backends[i].is_healthy) {
            healthy[healthy_count++] = &backends[i];
        }
        pthread_mutex_unlock(&backends[i].lock);
    }
    
    if (healthy_count == 0) {
        log_message(LOG_WARNING, "No healthy backends available");
        return NULL;
    }
    
    Backend *selected = NULL;
    
    switch (strategy) {
        case LB_ROUND_ROBIN: {
            pthread_mutex_lock(&rr_mutex);
            for (int i = 0; i < healthy_count; i++) {
                int idx = (round_robin_index + i) % healthy_count;
                log_message(LOG_DEBUG, "RR debug: index=%d, healthy_count=%d, idx=%d", 
                           round_robin_index, healthy_count, idx);
                selected = healthy[idx];
                round_robin_index = (idx + 1) % healthy_count;
                log_message(LOG_INFO, "Selected backend: %s:%d", selected->host, selected->port);
                break;
            }
            pthread_mutex_unlock(&rr_mutex);
            break;
        }
        
        case LB_LEAST_CONNECTIONS: {
            int min_connections = INT_MAX;
            
            for (int i = 0; i < healthy_count; i++) {
                pthread_mutex_lock(&healthy[i]->lock);
                int connections = healthy[i]->current_connections;
                pthread_mutex_unlock(&healthy[i]->lock);
                
                if (connections < min_connections) {
                    min_connections = connections;
                    selected = healthy[i];
                }
            }
            break;
        }
        
        case LB_IP_HASH: {
            if (client_ip) {
                unsigned int hash = hash_string(client_ip);
                int idx = hash % healthy_count;
                selected = healthy[idx];
            } else {
                pthread_mutex_lock(&rr_mutex);
                selected = healthy[round_robin_index % healthy_count];
                round_robin_index = (round_robin_index + 1) % healthy_count;
                pthread_mutex_unlock(&rr_mutex);
            }
            break;
        }
        
        case LB_WEIGHTED_ROUND_ROBIN: {
            static int current_weight = 0;
            static int current_index = -1;
            
            pthread_mutex_lock(&rr_mutex);
            
            while (1) {
                current_index = (current_index + 1) % healthy_count;
                if (current_index == 0) {
                    current_weight--;
                    if (current_weight <= 0) {
                        current_weight = get_total_backends_weight(backends, count);
                        if (current_weight == 0) {
                            current_weight = 1;
                        }
                    }
                }
                
                pthread_mutex_lock(&healthy[current_index]->lock);
                int weight = healthy[current_index]->weight;
                pthread_mutex_unlock(&healthy[current_index]->lock);
                
                if (weight >= current_weight) {
                    selected = healthy[current_index];
                    break;
                }
            }
            
            pthread_mutex_unlock(&rr_mutex);
            break;
        }
    }
    
    if (selected) {
        increment_backend_connections(selected);
        log_message(LOG_DEBUG, "Selected backend %s:%d (strategy: %d)", 
                   selected->host, selected->port, strategy);
    }
    
    return selected;
}

void print_load_balancing_stats(Backend *backends, int count) {
    log_message(LOG_INFO, "=== Load Balancing Statistics ===");
    
    int total_connections = 0;
    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&backends[i].lock);
        total_connections += backends[i].current_connections;
        pthread_mutex_unlock(&backends[i].lock);
    }
    
    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&backends[i].lock);
        float percentage = total_connections > 0 ? 
            (backends[i].current_connections * 100.0) / total_connections : 0;
        
        log_message(LOG_INFO, "[%d] %s:%d - Connections: %d (%.1f%%)", 
                   i, backends[i].host, backends[i].port,
                   backends[i].current_connections, percentage);
        pthread_mutex_unlock(&backends[i].lock);
    }
}

void reset_backend_stats(Backend *backends, int count) {
    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&backends[i].lock);
        backends[i].current_connections = 0;
        pthread_mutex_unlock(&backends[i].lock);
    }
    log_message(LOG_INFO, "Backend statistics reset");
}