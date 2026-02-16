/*
 * cache.c - Implémentation du système de cache HTTP
 * 
 * Ce module implémente un cache LRU (Least Recently Used) utilisant :
 * - Une table de hachage pour un accès rapide O(1) par clé
 * - Une liste doublement chaînée pour l'ordre LRU (éviction du plus ancien)
 * - Des hash SHA-256 pour vérifier l'intégrité des données
 * - Un mutex pour la sécurité multi-thread
 * 
 * Quand le cache est plein, l'entrée la moins récemment utilisée est évincée.
 */

#include "cache.h"
#include "utils.h"
#include <openssl/sha.h>   /* Pour le calcul de hash SHA-256 */
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * cache_init - Crée et initialise un nouveau cache
 * @capacity: nombre maximum d'entrées dans le cache
 * @return: pointeur vers le cache créé
 *
 * Alloue la structure du cache et initialise le tableau de buckets
 * (table de hachage) avec des pointeurs NULL.
 */
Cache* cache_init(int capacity) {
    Cache *cache = malloc(sizeof(Cache));
    cache->capacity = capacity;
    cache->count = 0;
    cache->total_size = 0;
    cache->buckets = calloc(capacity, sizeof(CacheEntry*));  /* calloc met tout à NULL */
    cache->lru_head = NULL;  /* La liste LRU est vide au départ */
    cache->lru_tail = NULL;
    pthread_mutex_init(&cache->lock, NULL);
    
    log_message(LOG_INFO, "Cache initialized with capacity %d", capacity);
    return cache;
}

/*
 * cache_free - Libère complètement le cache
 * @cache: le cache à détruire
 * Vide le cache, libère les buckets, détruit le mutex, puis libère la structure.
 */
void cache_free(Cache *cache) {
    cache_clear(cache);                    /* Supprimer toutes les entrées */
    free(cache->buckets);                  /* Libérer le tableau de buckets */
    pthread_mutex_destroy(&cache->lock);   /* Détruire le mutex */
    free(cache);                           /* Libérer la structure elle-même */
}

/*
 * remove_from_lru - Retire une entrée de la liste LRU (usage interne)
 * @cache: le cache contenant la liste LRU
 * @entry: l'entrée à retirer
 *
 * Met à jour les pointeurs prev/next des voisins et les pointeurs
 * head/tail du cache si nécessaire.
 */
static void remove_from_lru(Cache *cache, CacheEntry *entry) {
    /* Relier le précédent au suivant */
    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        cache->lru_head = entry->next;  /* L'entrée était la tête de liste */
    }
    
    /* Relier le suivant au précédent */
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        cache->lru_tail = entry->prev;  /* L'entrée était la queue de liste */
    }
}

/*
 * add_to_lru_head - Ajoute une entrée en tête de la liste LRU (usage interne)
 * @cache: le cache contenant la liste LRU
 * @entry: l'entrée à ajouter
 *
 * L'élément en tête est le plus récemment utilisé.
 */
static void add_to_lru_head(Cache *cache, CacheEntry *entry) {
    entry->prev = NULL;
    entry->next = cache->lru_head;
    
    if (cache->lru_head) {
        cache->lru_head->prev = entry;
    }
    cache->lru_head = entry;
    
    /* Si la liste était vide, l'entrée est aussi la queue */
    if (!cache->lru_tail) {
        cache->lru_tail = entry;
    }
}

/*
 * move_to_lru_head - Déplace une entrée existante en tête de la liste LRU
 * @cache: le cache contenant la liste LRU
 * @entry: l'entrée à déplacer
 *
 * Appelé à chaque accès (GET) pour marquer l'entrée comme récemment utilisée.
 */
static void move_to_lru_head(Cache *cache, CacheEntry *entry) {
    if (cache->lru_head == entry) return;  /* Déjà en tête, rien à faire */
    
    remove_from_lru(cache, entry);    /* Retirer de sa position actuelle */
    add_to_lru_head(cache, entry);    /* Ajouter en tête */
}

/*
 * evict_lru - Évince l'entrée la moins récemment utilisée (queue de la liste)
 * @cache: le cache dans lequel évincer
 *
 * 1. Trouve l'entrée en queue de la liste LRU
 * 2. La retire de la table de hachage (bucket)
 * 3. La retire de la liste LRU
 * 4. Met à jour les compteurs et libère la mémoire
 */
static void evict_lru(Cache *cache) {
    if (!cache->lru_tail) return;  /* Cache vide, rien à évincer */
    
    CacheEntry *to_remove = cache->lru_tail;
    
    /* Trouver et retirer l'entrée de la table de hachage */
    unsigned int hash = hash_string(to_remove->key) % cache->capacity;
    CacheEntry *curr = cache->buckets[hash];
    CacheEntry *prev = NULL;
    
    while (curr) {
        if (curr == to_remove) {
            if (prev) {
                prev->next = curr->next;
            } else {
                cache->buckets[hash] = curr->next;  /* C'était le premier du bucket */
            }
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    
    /* Retirer de la liste LRU */
    remove_from_lru(cache, to_remove);
    
    /* Mettre à jour les compteurs */
    cache->count--;
    cache->total_size -= to_remove->size;
    
    log_message(LOG_DEBUG, "Evicted cache entry: %s", to_remove->key);
    
    /* Libérer la mémoire */
    free(to_remove->data);
    free(to_remove);
}

/*
 * cache_remove_internal - Version interne de suppression (sans verrouillage)
 * @cache: le cache
 * @key: clé de l'entrée à supprimer
 *
 * Appelée uniquement quand le mutex est déjà verrouillé (depuis cache_get
 * pour supprimer une entrée expirée).
 */
// Version interne sans lock (appelée quand le lock est déjà pris)
static void cache_remove_internal(Cache *cache, const char *key) {
    unsigned int hash = hash_string(key) % cache->capacity;
    CacheEntry *curr = cache->buckets[hash];
    CacheEntry *prev = NULL;

    while (curr) {
        if (strcmp(curr->key, key) == 0) {
            /* Retirer du bucket de la table de hachage */
            if (prev) {
                prev->next = curr->next;
            } else {
                cache->buckets[hash] = curr->next;
            }
            /* Retirer de la liste LRU et libérer */
            remove_from_lru(cache, curr);
            cache->count--;
            cache->total_size -= curr->size;
            free(curr->data);
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
}

/*
 * cache_get - Récupère une entrée du cache par sa clé
 * @cache: le cache
 * @key: clé de l'entrée recherchée
 * @return: copie des données (à libérer avec free()), ou NULL si non trouvée/expirée
 *
 * 1. Calcule le hash de la clé pour trouver le bon bucket
 * 2. Parcourt la liste chaînée du bucket pour trouver la clé
 * 3. Si trouvée mais expirée : supprime l'entrée et retourne NULL
 * 4. Si trouvée et valide : déplace en tête LRU et retourne une copie des données
 */
char* cache_get(Cache *cache, const char *key) {
    pthread_mutex_lock(&cache->lock);
    
    /* Trouver le bucket correspondant au hash de la clé */
    unsigned int hash = hash_string(key) % cache->capacity;
    CacheEntry *entry = cache->buckets[hash];
    
    /* Parcourir la chaîne du bucket */
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            /* Vérifier si l'entrée a expiré */
            if (time(NULL) > entry->expiry) {
                cache_remove_internal(cache, key);  /* Supprimer l'entrée expirée */
                pthread_mutex_unlock(&cache->lock);
                return NULL;
            }
            
            /* Marquer comme récemment utilisée */
            move_to_lru_head(cache, entry);
            
            /* Créer une copie des données pour le retour */
            char *data_copy = malloc(entry->size + 1);
            memcpy(data_copy, entry->data, entry->size);
            data_copy[entry->size] = '\0';
            
            pthread_mutex_unlock(&cache->lock);
            log_message(LOG_DEBUG, "Cache HIT for: %s", key);
            return data_copy;  /* Cache HIT ! */
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_DEBUG, "Cache MISS for: %s", key);
    return NULL;  /* Cache MISS */
}

/*
 * cache_put - Ajoute ou met à jour une entrée dans le cache
 * @cache: le cache
 * @key: clé d'identification
 * @data: données à stocker
 * @size: taille des données en octets
 * @expiry: date d'expiration (timestamp Unix), 0 = défaut 1 heure
 *
 * Si le cache est plein, évince les entrées les moins récemment utilisées.
 * Calcule un hash SHA-256 du contenu pour l'intégrité.
 */
void cache_put(Cache *cache, const char *key, const char *data, size_t size, time_t expiry) {
    /* Rejeter les entrées trop volumineuses */
    if (size > MAX_CACHE_ENTRY_SIZE) {
        log_message(LOG_DEBUG, "Cache entry too large: %zu bytes", size);
        return;
    }
    
    pthread_mutex_lock(&cache->lock);
    
    /* Évincer des entrées si nécessaire pour faire de la place */
    while (cache->count >= cache->capacity || 
           (cache->total_size + size > CACHE_CAPACITY * MAX_CACHE_ENTRY_SIZE)) {
        evict_lru(cache);
    }
    
    /* Créer la nouvelle entrée */
    CacheEntry *entry = malloc(sizeof(CacheEntry));
    strncpy(entry->key, key, sizeof(entry->key) - 1);
    entry->key[sizeof(entry->key) - 1] = '\0';
    
    /* Copier les données */
    entry->data = malloc(size);
    memcpy(entry->data, data, size);
    entry->size = size;
    entry->timestamp = time(NULL);
    entry->expiry = expiry > 0 ? expiry : entry->timestamp + 3600;  /* Défaut : 1 heure */
    entry->next = NULL;
    entry->prev = NULL;
    
    /* Calculer le hash SHA-256 pour vérification d'intégrité */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data, size, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(entry->hash_key + (i * 2), "%02x", hash[i]);  /* Convertir en hexadécimal */
    }
    
    /* Insérer dans la table de hachage (en tête du bucket) */
    unsigned int hash_idx = hash_string(key) % cache->capacity;
    entry->next = cache->buckets[hash_idx];
    if (cache->buckets[hash_idx]) {
        cache->buckets[hash_idx]->prev = entry;
    }
    cache->buckets[hash_idx] = entry;
    
    /* Ajouter en tête de la liste LRU (élément le plus récent) */
    add_to_lru_head(cache, entry);
    
    /* Mettre à jour les compteurs */
    cache->count++;
    cache->total_size += size;
    
    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_DEBUG, "Cache PUT: %s (%zu bytes)", key, size);
}

/*
 * cache_remove - Supprime une entrée du cache par sa clé (version publique)
 * @cache: le cache
 * @key: clé de l'entrée à supprimer
 *
 * Version thread-safe avec verrouillage du mutex.
 */
void cache_remove(Cache *cache, const char *key) {
    pthread_mutex_lock(&cache->lock);
    
    unsigned int hash = hash_string(key) % cache->capacity;
    CacheEntry *curr = cache->buckets[hash];
    CacheEntry *prev = NULL;
    
    while (curr) {
        if (strcmp(curr->key, key) == 0) {
            /* Retirer du bucket de la table de hachage */
            if (prev) {
                prev->next = curr->next;
            } else {
                cache->buckets[hash] = curr->next;
            }
            
            /* Retirer de la liste LRU */
            remove_from_lru(cache, curr);
            
            /* Mettre à jour les compteurs */
            cache->count--;
            cache->total_size -= curr->size;
            
            /* Libérer la mémoire */
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

/*
 * cache_clear - Vide complètement le cache
 * @cache: le cache à vider
 *
 * Parcourt tous les buckets et libère toutes les entrées.
 * Réinitialise les compteurs et les pointeurs LRU.
 */
void cache_clear(Cache *cache) {
    pthread_mutex_lock(&cache->lock);
    
    /* Parcourir tous les buckets et libérer chaque entrée */
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
    
    /* Réinitialiser tous les compteurs */
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    cache->count = 0;
    cache->total_size = 0;
    
    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_INFO, "Cache cleared");
}

/*
 * cache_print_stats - Affiche les statistiques du cache
 * @cache: le cache
 *
 * Affiche : nombre d'entrées, taille totale, buckets vides (pour mesurer
 * la qualité de la distribution du hash), et longueur max de chaîne
 * (pour détecter les collisions excessives).
 */
void cache_print_stats(Cache *cache) {
    pthread_mutex_lock(&cache->lock);
    
    log_message(LOG_INFO, "=== Cache Statistics ===");
    log_message(LOG_INFO, "Entries: %d/%d", cache->count, cache->capacity);
    log_message(LOG_INFO, "Total size: %.2f MB", cache->total_size / (1024.0 * 1024.0));
    
    /* Analyser la distribution dans les buckets */
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
    
    /* Plus il y a de buckets vides, moins le hash distribue bien */
    log_message(LOG_INFO, "Empty buckets: %d/%d (%.1f%%)", 
                empty_buckets, cache->capacity, 
                (empty_buckets * 100.0) / cache->capacity);
    /* Une chaîne longue signifie beaucoup de collisions de hash */
    log_message(LOG_INFO, "Max chain length: %d", max_chain_length);
    
    pthread_mutex_unlock(&cache->lock);
}

/*
 * should_cache_request - Vérifie si une requête HTTP est éligible au cache
 * @request: la requête HTTP brute
 * @return: 1 si cacheable, 0 sinon
 *
 * Seules les requêtes GET sont cacheables.
 * Les requêtes avec Cache-Control: no-cache ou no-store sont exclues.
 */
int should_cache_request(const char *request) {
    /* Seules les requêtes GET sont cacheables */
    if (strncmp(request, "GET ", 4) != 0) {
        return 0;
    }
    
    /* Respecter les directives Cache-Control du client */
    const char *no_cache = strstr(request, "Cache-Control: no-cache");
    const char *no_store = strstr(request, "Cache-Control: no-store");
    
    if (no_cache || no_store) {
        return 0;  /* Le client ne veut pas de cache */
    }
    
    return 1;
}

/*
 * should_cache_response - Vérifie si une réponse HTTP est éligible au cache
 * @response: la réponse HTTP brute
 * @return: 1 si cacheable, 0 sinon
 *
 * Conditions pour cacher une réponse :
 * - Code 200 OK ou 304 Not Modified
 * - Pas de Cache-Control: no-store ou private
 * - Content-Type dans la liste des types cacheables (HTML, CSS, JS, images)
 */
int should_cache_response(const char *response) {
    /* Seules les réponses 200 et 304 sont cacheables */
    if (strncmp(response, "HTTP/1.1 200", 12) != 0 &&
        strncmp(response, "HTTP/1.1 304", 12) != 0) {
        return 0;
    }
    
    /* Respecter les directives Cache-Control du serveur */
    const char *no_store = strstr(response, "Cache-Control: no-store");
    const char *private_header = strstr(response, "Cache-Control: private");
    
    if (no_store || private_header) {
        return 0;  /* Le serveur interdit le cache */
    }
    
    /* Vérifier que le Content-Type est un type cacheable */
    const char *content_type = strstr(response, "Content-Type:");
    if (content_type) {
        if (strstr(content_type, "text/html") ||
            strstr(content_type, "text/css") ||
            strstr(content_type, "application/javascript") ||
            strstr(content_type, "image/")) {
            return 1;  /* Type cacheable */
        }
    }
    
    return 0;
}

/*
 * get_cache_expiry_from_headers - Extrait la durée d'expiration des en-têtes HTTP
 * @headers: les en-têtes HTTP de la réponse
 * @return: timestamp Unix d'expiration
 *
 * Priorité : Cache-Control: max-age > Expires header > défaut (1 heure).
 * Si les deux sont présents, utilise le plus restrictif.
 */
time_t get_cache_expiry_from_headers(const char *headers) {
    time_t now = time(NULL);
    time_t expiry = now + 3600;  /* Défaut : 1 heure */
    
    /* Chercher Cache-Control: max-age=<seconds> */
    const char *cache_control = strstr(headers, "Cache-Control:");
    if (cache_control) {
        const char *max_age = strstr(cache_control, "max-age=");
        if (max_age) {
            int seconds = atoi(max_age + 8);  /* +8 pour sauter "max-age=" */
            if (seconds > 0) {
                expiry = now + seconds;
            }
        }
    }
    
    /* Chercher Expires: <date RFC 2616> */
    const char *expires_header = strstr(headers, "Expires:");
    if (expires_header) {
        struct tm tm;
        memset(&tm, 0, sizeof(tm));
        /* Parser la date au format HTTP (ex: "Thu, 01 Jan 2026 00:00:00 GMT") */
        if (strptime(expires_header + 8, "%a, %d %b %Y %H:%M:%S", &tm)) {
            time_t expires_time = mktime(&tm);
            if (expires_time > now) {
                expiry = expires_time;
            }
        }
    }
    
    return expiry;
}

/*
 * cache_rules_init - Crée une structure vide pour les règles de cache
 * @return: pointeur vers les règles initialisées
 *
 * Alloue un tableau dynamique initial de 10 règles.
 */
CacheRules* cache_rules_init(void) {
    CacheRules *rules = malloc(sizeof(CacheRules));
    rules->capacity = 10;   /* Capacité initiale */
    rules->count = 0;
    rules->rules = malloc(sizeof(CacheRule) * rules->capacity);
    return rules;
}

/*
 * cache_rules_free - Libère les règles de cache
 * @rules: les règles à libérer
 */
void cache_rules_free(CacheRules *rules) {
    free(rules->rules);
    free(rules);
}

/*
 * cache_rules_load - Charge les règles de cache depuis un fichier
 * @rules: structure où stocker les règles
 * @filename: chemin du fichier (ex: "config/cache_rules.cfg")
 * @return: 1 si succès, 0 si erreur
 *
 * Format du fichier : une règle par ligne
 *   patron:max_age:max_size
 * Exemple : *.html:3600:1048576  (HTML, 1h de cache, max 1 Mo)
 * Les lignes commençant par '#' sont des commentaires.
 */
int cache_rules_load(CacheRules *rules, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_message(LOG_ERROR, "Failed to open cache rules file: %s", filename);
        return 0;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        /* Ignorer les commentaires et les lignes vides */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        /* Parser les 3 champs séparés par ':' */
        char *pattern = strtok(line, ":");
        char *max_age_str = strtok(NULL, ":");
        char *max_size_str = strtok(NULL, ":\n\r");
        
        if (!pattern || !max_age_str || !max_size_str) {
            log_message(LOG_WARNING, "Invalid cache rule format: %s", line);
            continue;
        }
        
        /* Agrandir le tableau si nécessaire (doublement de capacité) */
        if (rules->count >= rules->capacity) {
            rules->capacity *= 2;
            rules->rules = realloc(rules->rules, sizeof(CacheRule) * rules->capacity);
        }
        
        /* Ajouter la nouvelle règle */
        CacheRule *rule = &rules->rules[rules->count++];
        strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
        rule->pattern[sizeof(rule->pattern) - 1] = '\0';
        rule->max_age = atoi(max_age_str);          /* Durée max en secondes */
        rule->max_size = (size_t)atol(max_size_str); /* Taille max en octets */
        
        log_message(LOG_DEBUG, "Loaded cache rule: %s:%d:%zu", rule->pattern, rule->max_age, rule->max_size);
    }
    
    fclose(file);
    log_message(LOG_INFO, "Loaded %d cache rules from %s", rules->count, filename);
    return 1;
}

/*
 * cache_rules_match - Vérifie si un chemin correspond à une règle de cache
 * @rules: les règles à vérifier
 * @path: chemin de la requête (ex: "/page.html")
 * @max_age: [sortie] durée de cache en secondes si match trouvé
 * @max_size: [sortie] taille max de réponse cacheable si match trouvé
 * @return: 1 si une règle correspond, 0 sinon
 *
 * Parcourt les règles dans l'ordre et retourne la première qui correspond.
 * Utilise match_pattern() pour la correspondance avec wildcards.
 */
int cache_rules_match(CacheRules *rules, const char *path, int *max_age, size_t *max_size) {
    for (int i = 0; i < rules->count; i++) {
        CacheRule *rule = &rules->rules[i];
        
        if (match_pattern(rule->pattern, path)) {
            *max_age = rule->max_age;
            *max_size = rule->max_size;
            log_message(LOG_DEBUG, "Cache rule matched: %s -> %s (age=%d, size=%zu)", 
                       path, rule->pattern, rule->max_age, rule->max_size);
            return 1;  /* Première règle qui correspond */
        }
    }
    log_message(LOG_DEBUG, "No cache rule matched for: %s", path);
    return 0;  /* Aucune règle ne correspond */
}