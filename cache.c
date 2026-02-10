#include "cache.h"
#include "utils.h"
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

Cache* cache_init(int capacity) {
    Cache *cache = malloc(sizeof(Cache));
    cache->capacity = capacity;
    cache->count = 0;
    cache->total_size = 0;
    cache->buckets = calloc(capacity, sizeof(CacheEntry*));
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    pthread_mutex_init(&cache->lock, NULL);
    
    log_message(LOG_INFO, "Cache initialized with capacity %d", capacity);
    return cache;
}

void cache_free(Cache *cache) {
    cache_clear(cache);
    free(cache->buckets);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

static void remove_from_lru(Cache *cache, CacheEntry *entry) {
    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        cache->lru_head = entry->next;
    }
    
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        cache->lru_tail = entry->prev;
    }
}

static void add_to_lru_head(Cache *cache, CacheEntry *entry) {
    entry->prev = NULL;
    entry->next = cache->lru_head;
    
    if (cache->lru_head) {
        cache->lru_head->prev = entry;
    }
    cache->lru_head = entry;
    
    if (!cache->lru_tail) {
        cache->lru_tail = entry;
    }
}

static void move_to_lru_head(Cache *cache, CacheEntry *entry) {
    if (cache->lru_head == entry) return;
    
    remove_from_lru(cache, entry);
    add_to_lru_head(cache, entry);
}

static void evict_lru(Cache *cache) {
    if (!cache->lru_tail) return;
    
    CacheEntry *to_remove = cache->lru_tail;
    
    unsigned int hash = hash_string(to_remove->key) % cache->capacity;
    CacheEntry *curr = cache->buckets[hash];
    CacheEntry *prev = NULL;
    
    while (curr) {
        if (curr == to_remove) {
            if (prev) {
                prev->next = curr->next;
            } else {
                cache->buckets[hash] = curr->next;
            }
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    
    remove_from_lru(cache, to_remove);
    
    cache->count--;
    cache->total_size -= to_remove->size;
    
    log_message(LOG_DEBUG, "Evicted cache entry: %s", to_remove->key);
    
    free(to_remove->data);
    free(to_remove);
}

char* cache_get(Cache *cache, const char *key) {
    pthread_mutex_lock(&cache->lock);
    
    unsigned int hash = hash_string(key) % cache->capacity;
    CacheEntry *entry = cache->buckets[hash];
    
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            if (time(NULL) > entry->expiry) {
                cache_remove(cache, key);
                pthread_mutex_unlock(&cache->lock);
                return NULL;
            }
            
            move_to_lru_head(cache, entry);
            
            char *data_copy = malloc(entry->size + 1);
            memcpy(data_copy, entry->data, entry->size);
            data_copy[entry->size] = '\0';
            
            pthread_mutex_unlock(&cache->lock);
            log_message(LOG_DEBUG, "Cache HIT for: %s", key);
            return data_copy;
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_DEBUG, "Cache MISS for: %s", key);
    return NULL;
}

void cache_put(Cache *cache, const char *key, const char *data, size_t size, time_t expiry) {
    if (size > MAX_CACHE_ENTRY_SIZE) {
        log_message(LOG_DEBUG, "Cache entry too large: %zu bytes", size);
        return;
    }
    
    pthread_mutex_lock(&cache->lock);
    
    while (cache->count >= cache->capacity || 
           (cache->total_size + size > CACHE_CAPACITY * MAX_CACHE_ENTRY_SIZE)) {
        evict_lru(cache);
    }
    
    CacheEntry *entry = malloc(sizeof(CacheEntry));
    strncpy(entry->key, key, sizeof(entry->key) - 1);
    entry->key[sizeof(entry->key) - 1] = '\0';
    
    entry->data = malloc(size);
    memcpy(entry->data, data, size);
    entry->size = size;
    entry->timestamp = time(NULL);
    entry->expiry = expiry > 0 ? expiry : entry->timestamp + 3600;
    entry->next = NULL;
    entry->prev = NULL;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data, size, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(entry->hash_key + (i * 2), "%02x", hash[i]);
    }
    
    unsigned int hash_idx = hash_string(key) % cache->capacity;
    entry->next = cache->buckets[hash_idx];
    if (cache->buckets[hash_idx]) {
        cache->buckets[hash_idx]->prev = entry;
    }
    cache->buckets[hash_idx] = entry;
    
    add_to_lru_head(cache, entry);
    
    cache->count++;
    cache->total_size += size;
    
    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_DEBUG, "Cache PUT: %s (%zu bytes)", key, size);
}

void cache_remove(Cache *cache, const char *key) {
    pthread_mutex_lock(&cache->lock);
    
    unsigned int hash = hash_string(key) % cache->capacity;
    CacheEntry *curr = cache->buckets[hash];
    CacheEntry *prev = NULL;
    
    while (curr) {
        if (strcmp(curr->key, key) == 0) {
            if (prev) {
                prev->next = curr->next;
            } else {
                cache->buckets[hash] = curr->next;
            }
            
            remove_from_lru(cache, curr);
            
            cache->count--;
            cache->total_size -= curr->size;
            
            free(curr->data);
            free(curr);
            
            log_message(LOG_DEBUG, "Cache REMOVE: %s", key);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    
    pthread_mutex_unlock(&cache->lock);
}

void cache_clear(Cache *cache) {
    pthread_mutex_lock(&cache->lock);
    
    for (int i = 0; i < cache->capacity; i++) {
        CacheEntry *entry = cache->buckets[i];
        while (entry) {
            CacheEntry *next = entry->next;
            free(entry->data);
            free(entry);
            entry = next;
        }
        cache->buckets[i] = NULL;
    }
    
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    cache->count = 0;
    cache->total_size = 0;
    
    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_INFO, "Cache cleared");
}

void cache_print_stats(Cache *cache) {
    pthread_mutex_lock(&cache->lock);
    
    log_message(LOG_INFO, "=== Cache Statistics ===");
    log_message(LOG_INFO, "Entries: %d/%d", cache->count, cache->capacity);
    log_message(LOG_INFO, "Total size: %.2f MB", cache->total_size / (1024.0 * 1024.0));
    
    int empty_buckets = 0;
    int max_chain_length = 0;
    
    for (int i = 0; i < cache->capacity; i++) {
        int chain_length = 0;
        CacheEntry *entry = cache->buckets[i];
        
        while (entry) {
            chain_length++;
            entry = entry->next;
        }
        
        if (chain_length == 0) empty_buckets++;
        if (chain_length > max_chain_length) max_chain_length = chain_length;
    }
    
    log_message(LOG_INFO, "Empty buckets: %d/%d (%.1f%%)", 
                empty_buckets, cache->capacity, 
                (empty_buckets * 100.0) / cache->capacity);
    log_message(LOG_INFO, "Max chain length: %d", max_chain_length);
    
    pthread_mutex_unlock(&cache->lock);
}

int should_cache_request(const char *request) {
    if (strncmp(request, "GET ", 4) != 0) {
        return 0;
    }
    
    const char *no_cache = strstr(request, "Cache-Control: no-cache");
    const char *no_store = strstr(request, "Cache-Control: no-store");
    
    if (no_cache || no_store) {
        return 0;
    }
    
    return 1;
}

int should_cache_response(const char *response) {
    if (strncmp(response, "HTTP/1.1 200", 12) != 0 &&
        strncmp(response, "HTTP/1.1 304", 12) != 0) {
        return 0;
    }
    
    const char *no_store = strstr(response, "Cache-Control: no-store");
    const char *private_header = strstr(response, "Cache-Control: private");
    
    if (no_store || private_header) {
        return 0;
    }
    
    const char *content_type = strstr(response, "Content-Type:");
    if (content_type) {
        if (strstr(content_type, "text/html") ||
            strstr(content_type, "text/css") ||
            strstr(content_type, "application/javascript") ||
            strstr(content_type, "image/")) {
            return 1;
        }
    }
    
    return 0;
}

time_t get_cache_expiry_from_headers(const char *headers) {
    time_t now = time(NULL);
    time_t expiry = now + 3600;
    
    const char *cache_control = strstr(headers, "Cache-Control:");
    if (cache_control) {
        const char *max_age = strstr(cache_control, "max-age=");
        if (max_age) {
            int seconds = atoi(max_age + 8);
            if (seconds > 0) {
                expiry = now + seconds;
            }
        }
    }
    
    const char *expires_header = strstr(headers, "Expires:");
    if (expires_header) {
        struct tm tm;
        memset(&tm, 0, sizeof(tm));
        if (strptime(expires_header + 8, "%a, %d %b %Y %H:%M:%S", &tm)) {
            time_t expires_time = mktime(&tm);
            if (expires_time > now) {
                expiry = expires_time;
            }
        }
    }
    
    return expiry;
}

CacheRules* cache_rules_init(void) {
    CacheRules *rules = malloc(sizeof(CacheRules));
    rules->capacity = 10;
    rules->count = 0;
    rules->rules = malloc(sizeof(CacheRule) * rules->capacity);
    return rules;
}

void cache_rules_free(CacheRules *rules) {
    free(rules->rules);
    free(rules);
}

int cache_rules_load(CacheRules *rules, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_message(LOG_ERROR, "Failed to open cache rules file: %s", filename);
        return 0;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        char *pattern = strtok(line, ":");
        char *max_age_str = strtok(NULL, ":");
        char *max_size_str = strtok(NULL, ":\n\r");
        
        if (!pattern || !max_age_str || !max_size_str) {
            log_message(LOG_WARNING, "Invalid cache rule format: %s", line);
            continue;
        }
        
        if (rules->count >= rules->capacity) {
            rules->capacity *= 2;
            rules->rules = realloc(rules->rules, sizeof(CacheRule) * rules->capacity);
        }
        
        CacheRule *rule = &rules->rules[rules->count++];
        strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
        rule->pattern[sizeof(rule->pattern) - 1] = '\0';
        rule->max_age = atoi(max_age_str);
        rule->max_size = (size_t)atol(max_size_str);
        
        log_message(LOG_DEBUG, "Loaded cache rule: %s:%d:%zu", rule->pattern, rule->max_age, rule->max_size);
    }
    
    fclose(file);
    log_message(LOG_INFO, "Loaded %d cache rules from %s", rules->count, filename);
    return 1;
}

int cache_rules_match(CacheRules *rules, const char *path, int *max_age, size_t *max_size) {
    for (int i = 0; i < rules->count; i++) {
        CacheRule *rule = &rules->rules[i];
        
        if (match_pattern(rule->pattern, path)) {
            *max_age = rule->max_age;
            *max_size = rule->max_size;
            log_message(LOG_DEBUG, "Cache rule matched: %s -> %s (age=%d, size=%zu)", 
                       path, rule->pattern, rule->max_age, rule->max_size);
            return 1;
        }
    }
    log_message(LOG_DEBUG, "No cache rule matched for: %s", path);
    return 0;
}