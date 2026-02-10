#include "backend_manager.h"
#include "utils.h"
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

Backend* load_backends(const char *filename, int *count) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        log_message(LOG_ERROR, "Cannot open backends file: %s", filename);
        return NULL;
    }
    
    Backend *backends = malloc(MAX_BACKENDS * sizeof(Backend));
    *count = 0;
    
    char line[512];
    while (fgets(line, sizeof(line), f) && *count < MAX_BACKENDS) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        line[strcspn(line, "\n")] = 0;
        
        Backend *b = &backends[*count];
        memset(b, 0, sizeof(Backend));
        pthread_mutex_init(&b->lock, NULL);
        
        char *token = strtok(line, ":");
        if (token) strncpy(b->host, token, sizeof(b->host) - 1);
        
        token = strtok(NULL, ":");
        if (token) b->port = atoi(token);
        
        token = strtok(NULL, ":");
        if (token) b->weight = atoi(token);
        
        token = strtok(NULL, ":");
        if (token) b->max_failures = atoi(token);
        
        b->is_healthy = 1;
        b->failures = 0;
        b->current_connections = 0;
        b->last_check = time(NULL);
        
        if (b->weight <= 0) b->weight = 1;
        if (b->max_failures <= 0) b->max_failures = 3;
        
        (*count)++;
        
        log_message(LOG_INFO, "Loaded backend: %s:%d (weight: %d, max failures: %d)", 
                   b->host, b->port, b->weight, b->max_failures);
    }
    
    fclose(f);
    return backends;
}

void free_backends(Backend *backends, int count) {
    for (int i = 0; i < count; i++) {
        pthread_mutex_destroy(&backends[i].lock);
    }
    free(backends);
}

void increment_backend_connections(Backend *backend) {
    pthread_mutex_lock(&backend->lock);
    backend->current_connections++;
    pthread_mutex_unlock(&backend->lock);
}

void decrement_backend_connections(Backend *backend) {
    pthread_mutex_lock(&backend->lock);
    if (backend->current_connections > 0) {
        backend->current_connections--;
    }
    pthread_mutex_unlock(&backend->lock);
}

void update_backend_health(Backend *backend, int is_healthy) {
    pthread_mutex_lock(&backend->lock);
    
    backend->last_check = time(NULL);
    
    if (is_healthy) {
        backend->failures = 0;
        if (!backend->is_healthy) {
            backend->is_healthy = 1;
            log_message(LOG_INFO, "Backend %s:%d is now HEALTHY", 
                       backend->host, backend->port);
        }
    } else {
        backend->failures++;
        if (backend->failures >= backend->max_failures && backend->is_healthy) {
            backend->is_healthy = 0;
            log_message(LOG_WARNING, "Backend %s:%d is now UNHEALTHY (%d failures)", 
                       backend->host, backend->port, backend->failures);
        }
    }
    
    pthread_mutex_unlock(&backend->lock);
}

void* health_check_thread(void *arg) {
    typedef struct {
        Backend *backends;
        int count;
    } HealthArgs;
    HealthArgs *args = (HealthArgs *)arg;
    Backend *backends = args->backends;
    int count = args->count;
    
    log_message(LOG_INFO, "Health check thread started");
    
    while (1) {
        for (int i = 0; i < count; i++) {
            Backend *b = &backends[i];
            
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                update_backend_health(b, 0);
                continue;
            }
            
            set_socket_timeout(sock, 2);
            
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(b->port);
            
            int connected = 0;
            if (inet_pton(AF_INET, b->host, &addr.sin_addr) > 0) {
                if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    connected = 1;
                }
            } else {
                struct hostent *he = gethostbyname(b->host);
                if (he) {
                    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
                    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                        connected = 1;
                    }
                }
            }
            
            close(sock);
            update_backend_health(b, connected);
        }
        
        sleep(HEALTH_CHECK_INTERVAL);
    }
    
    return NULL;
}

int get_total_backends_weight(Backend *backends, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        if (backends[i].is_healthy) {
            total += backends[i].weight;
        }
    }
    return total;
}

void print_backend_stats(Backend *backends, int count) {
    log_message(LOG_INFO, "=== Backend Statistics ===");
    for (int i = 0; i < count; i++) {
        log_message(LOG_INFO, "[%d] %s:%d - Connections: %d, Healthy: %s, Weight: %d", 
                   i, backends[i].host, backends[i].port,
                   backends[i].current_connections,
                   backends[i].is_healthy ? "YES" : "NO",
                   backends[i].weight);
    }
}