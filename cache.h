/*
 * cache.h - Interface du système de cache HTTP
 * Fournit les fonctions pour stocker et récupérer les réponses HTTP
 * en cache, avec un algorithme d'éviction LRU (Least Recently Used)
 * et des règles de mise en cache configurables.
 */

#ifndef CACHE_H
#define CACHE_H

#include "config.h"

/* === Gestion du cache === */

/* Crée et initialise un cache avec la capacité donnée (nombre max d'entrées) */
Cache* cache_init(int capacity);

/* Libère toute la mémoire du cache (entrées + structure) */
void cache_free(Cache *cache);

/* Récupère une entrée du cache par sa clé (retourne NULL si absente ou expirée) */
char* cache_get(Cache *cache, const char *key);

/* Ajoute ou met à jour une entrée dans le cache avec une date d'expiration */
void cache_put(Cache *cache, const char *key, const char *data, size_t size, time_t expiry);

/* Supprime une entrée spécifique du cache par sa clé */
void cache_remove(Cache *cache, const char *key);

/* Vide complètement le cache (supprime toutes les entrées) */
void cache_clear(Cache *cache);

/* Affiche les statistiques du cache dans le journal */
void cache_print_stats(Cache *cache);

/* === Analyse des requêtes/réponses pour le cache === */

/* Vérifie si une requête HTTP est cacheable (GET uniquement, pas de no-cache) */
int should_cache_request(const char *request);

/* Vérifie si une réponse HTTP est cacheable (200/304, types MIME acceptés) */
int should_cache_response(const char *response);

/* Extrait la durée d'expiration depuis les en-têtes HTTP (Cache-Control, Expires) */
time_t get_cache_expiry_from_headers(const char *headers);

/* === Règles de cache configurables === */

/* Crée une structure vide pour les règles de cache */
CacheRules* cache_rules_init(void);

/* Libère les règles de cache */
void cache_rules_free(CacheRules *rules);

/* Charge les règles de cache depuis un fichier de configuration */
int cache_rules_load(CacheRules *rules, const char *filename);

/* Vérifie si un chemin correspond à une règle de cache (retourne max_age et max_size) */
int cache_rules_match(CacheRules *rules, const char *path, int *max_age, size_t *max_size);

#endif