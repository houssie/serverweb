#ifndef CACHE_H
#define CACHE_H

#include "config.h"

Cache* cache_init(int capacity);
void cache_free(Cache *cache);
char* cache_get(Cache *cache, const char *key);
void cache_put(Cache *cache, const char *key, const char *data, size_t size, time_t expiry);
void cache_remove(Cache *cache, const char *key);
void cache_clear(Cache *cache);
void cache_print_stats(Cache *cache);
int should_cache_request(const char *request);
int should_cache_response(const char *response);
time_t get_cache_expiry_from_headers(const char *headers);

CacheRules* cache_rules_init(void);
void cache_rules_free(CacheRules *rules);
int cache_rules_load(CacheRules *rules, const char *filename);
int cache_rules_match(CacheRules *rules, const char *path, int *max_age, size_t *max_size);

#endif