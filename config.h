#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define MAX_BACKENDS 10
#define MAX_CLIENTS 100
#define BUFFER_SIZE 8192
#define CACHE_CAPACITY 100
#define MAX_CACHE_ENTRY_SIZE (10 * 1024 * 1024)
#define CACHE_KEY_SIZE 8192
#define HEALTH_CHECK_INTERVAL 10
#define REQUEST_TIMEOUT 30

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

typedef struct {
    char host[256];
    int port;
    int weight;
    int current_connections;
    int is_healthy;
    time_t last_check;
    int failures;
    int max_failures;
    pthread_mutex_t lock;
} Backend;

struct CacheEntry {
    char key[512];
    char *data;
    size_t size;
    time_t timestamp;
    time_t expiry;
    struct CacheEntry *next;
    struct CacheEntry *prev;
    char hash_key[65];
};

typedef struct CacheEntry CacheEntry;

typedef struct {
    CacheEntry **buckets;
    int capacity;
    int count;
    CacheEntry *lru_head;
    CacheEntry *lru_tail;
    pthread_mutex_t lock;
    size_t total_size;
} Cache;

typedef struct {
    char pattern[256];
    int max_age;
    size_t max_size;
} CacheRule;

typedef struct {
    CacheRule *rules;
    int count;
    int capacity;
} CacheRules;

typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
    Backend *backends;
    int backend_count;
    Cache *cache;
    char client_ip[INET_ADDRSTRLEN];
} ClientArgs;

typedef struct {
    char method[16];
    char path[1024];
    char protocol[16];
    char host[256];
    int port;
    char headers[4096];
} HttpRequest;

typedef enum {
    LB_ROUND_ROBIN,
    LB_LEAST_CONNECTIONS,
    LB_IP_HASH,
    LB_WEIGHTED_ROUND_ROBIN
} LBStrategy;

void log_message(LogLevel level, const char *format, ...);
char* get_client_ip(struct sockaddr_in addr);
int parse_http_request(const char *raw, HttpRequest *req);
int should_cache_response(const char *response);
time_t get_cache_expiry(const char *headers);
char* generate_etag(const char *data, size_t size);

#endif