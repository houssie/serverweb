/*
 * load_balancer.c - Répartiteur de charge (Load Balancer)
 * 
 * Implémente 4 stratégies de répartition de charge :
 * 1. Round Robin : distribution tour à tour entre les backends
 * 2. Least Connections : envoie vers le backend le moins chargé
 * 3. IP Hash : même client toujours redirigé vers le même backend
 * 4. Weighted Round Robin : prend en compte le poids de chaque backend
 *
 * Seuls les backends en bonne santé (is_healthy=1) sont considérés.
 */

#include "load_balancer.h"
#include "utils.h"
#include "backend_manager.h"
#include <limits.h>
#include <string.h>

/* Compteur statique pour le Round Robin (persistant entre les appels) */
static int round_robin_index = 0;
/* Mutex pour protéger le compteur Round Robin en multi-thread */
static pthread_mutex_t rr_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * select_backend - Sélectionne un backend selon la stratégie configurée
 * @backends: tableau de tous les backends disponibles
 * @count: nombre total de backends
 * @strategy: stratégie de sélection (voir LBStrategy dans config.h)
 * @client_ip: adresse IP du client (utilisée pour IP Hash)
 * @return: pointeur vers le backend sélectionné, ou NULL si aucun n'est disponible
 *
 * 1. Filtre d'abord les backends en bonne santé
 * 2. Applique la stratégie choisie pour sélectionner parmi les backends sains
 * 3. Incrémente automatiquement le compteur de connexions du backend choisi
 */
Backend* select_backend(Backend *backends, int count, LBStrategy strategy, const char *client_ip) {
    if (count == 0) return NULL;
    
    /* Étape 1 : Construire la liste des backends en bonne santé */
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
        return NULL;  /* Aucun backend disponible */
    }
    
    Backend *selected = NULL;
    
    /* Étape 2 : Appliquer la stratégie de sélection */
    switch (strategy) {
        /*
         * ROUND ROBIN : Distribution tour à tour
         * Chaque backend reçoit une requête à son tour dans l'ordre.
         * Simple et équitable si les backends ont des performances similaires.
         */
        case LB_ROUND_ROBIN: {
            pthread_mutex_lock(&rr_mutex);
            for (int i = 0; i < healthy_count; i++) {
                int idx = (round_robin_index + i) % healthy_count;
                log_message(LOG_DEBUG, "RR debug: index=%d, healthy_count=%d, idx=%d", 
                           round_robin_index, healthy_count, idx);
                selected = healthy[idx];
                round_robin_index = (idx + 1) % healthy_count;  /* Avancer pour le prochain appel */
                log_message(LOG_INFO, "Selected backend: %s:%d", selected->host, selected->port);
                break;
            }
            pthread_mutex_unlock(&rr_mutex);
            break;
        }
        
        /*
         * LEAST CONNECTIONS : Moins de connexions
         * Envoie la requête vers le backend qui a le moins de connexions actives.
         * Idéal quand les requêtes ont des durées de traitement variables.
         */
        case LB_LEAST_CONNECTIONS: {
            int min_connections = INT_MAX;
            
            for (int i = 0; i < healthy_count; i++) {
                pthread_mutex_lock(&healthy[i]->lock);
                int connections = healthy[i]->current_connections;
                pthread_mutex_unlock(&healthy[i]->lock);
                
                /* Garder le backend avec le moins de connexions */
                if (connections < min_connections) {
                    min_connections = connections;
                    selected = healthy[i];
                }
            }
            break;
        }
        
        /*
         * IP HASH : Affinité de session par IP
         * Le hash de l'IP du client détermine le backend.
         * Garantit qu'un même client est toujours dirigé vers le même backend.
         * Utile pour les sessions côté serveur.
         */
        case LB_IP_HASH: {
            if (client_ip) {
                unsigned int hash = hash_string(client_ip);
                int idx = hash % healthy_count;  /* Le hash donne un index stable */
                selected = healthy[idx];
            } else {
                /* Fallback en Round Robin si pas d'IP client */
                pthread_mutex_lock(&rr_mutex);
                selected = healthy[round_robin_index % healthy_count];
                round_robin_index = (round_robin_index + 1) % healthy_count;
                pthread_mutex_unlock(&rr_mutex);
            }
            break;
        }
        
        /*
         * WEIGHTED ROUND ROBIN : Round Robin pondéré
         * Comme le Round Robin mais les backends avec un poids plus élevé
         * reçoivent proportionnellement plus de requêtes.
         * Ex: poids 3 reçoit 3x plus de requêtes que poids 1.
         */
        case LB_WEIGHTED_ROUND_ROBIN: {
            static int current_weight = 0;    /* Poids courant dans le cycle */
            static int current_index = -1;    /* Index courant dans le cycle */
            
            pthread_mutex_lock(&rr_mutex);
            
            while (1) {
                /* Passer au backend suivant */
                current_index = (current_index + 1) % healthy_count;
                
                /* Quand on revient au début, réduire le poids courant */
                if (current_index == 0) {
                    current_weight--;
                    if (current_weight <= 0) {
                        /* Réinitialiser au poids total */
                        current_weight = get_total_backends_weight(backends, count);
                        if (current_weight == 0) {
                            current_weight = 1;
                        }
                    }
                }
                
                /* Sélectionner si le backend a un poids suffisant */
                pthread_mutex_lock(&healthy[current_index]->lock);
                int weight = healthy[current_index]->weight;
                pthread_mutex_unlock(&healthy[current_index]->lock);
                
                if (weight >= current_weight) {
                    selected = healthy[current_index];
                    break;  /* Backend sélectionné ! */
                }
            }
            
            pthread_mutex_unlock(&rr_mutex);
            break;
        }
    }
    
    /* Étape 3 : Incrémenter les connexions du backend sélectionné */
    if (selected) {
        increment_backend_connections(selected);
        log_message(LOG_DEBUG, "Selected backend %s:%d (strategy: %d)", 
                   selected->host, selected->port, strategy);
    }
    
    return selected;
}

/*
 * print_load_balancing_stats - Affiche les statistiques de répartition
 * @backends: tableau de backends
 * @count: nombre de backends
 *
 * Affiche le nombre de connexions et le pourcentage de charge de chaque backend
 * par rapport au total. Utile pour vérifier que la répartition est équilibrée.
 */
void print_load_balancing_stats(Backend *backends, int count) {
    log_message(LOG_INFO, "=== Load Balancing Statistics ===");
    
    /* Calculer le total de connexions actives */
    int total_connections = 0;
    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&backends[i].lock);
        total_connections += backends[i].current_connections;
        pthread_mutex_unlock(&backends[i].lock);
    }
    
    /* Afficher chaque backend avec son pourcentage */
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

/*
 * reset_backend_stats - Remet à zéro les connexions de tous les backends
 * @backends: tableau de backends
 * @count: nombre de backends
 */
void reset_backend_stats(Backend *backends, int count) {
    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&backends[i].lock);
        backends[i].current_connections = 0;
        pthread_mutex_unlock(&backends[i].lock);
    }
    log_message(LOG_INFO, "Backend statistics reset");
}