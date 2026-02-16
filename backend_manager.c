/*
 * backend_manager.c - Gestion des serveurs backend
 * Gère le chargement de la configuration des backends,
 * la surveillance de leur état de santé (health checks),
 * et le suivi des connexions actives.
 */

#include "backend_manager.h"
#include "utils.h"
#include <netdb.h>       /* Pour gethostbyname() */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/*
 * load_backends - Charge la liste des serveurs backend depuis un fichier
 * @filename: chemin du fichier de configuration (ex: "config/backends.cfg")
 * @count: pointeur où stocker le nombre de backends chargés
 * @return: tableau de backends alloué dynamiquement, ou NULL en cas d'erreur
 *
 * Format du fichier : une ligne par backend
 *   host:port:poids:max_echecs
 * Exemple : 127.0.0.1:8081:1:3
 * Les lignes commençant par '#' sont des commentaires.
 */
Backend* load_backends(const char *filename, int *count) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        log_message(LOG_ERROR, "Cannot open backends file: %s", filename);
        return NULL;
    }
    
    /* Allouer le tableau de backends (taille max fixe) */
    Backend *backends = malloc(MAX_BACKENDS * sizeof(Backend));
    *count = 0;
    
    char line[512];
    while (fgets(line, sizeof(line), f) && *count < MAX_BACKENDS) {
        /* Ignorer les commentaires et les lignes vides */
        if (line[0] == '#' || line[0] == '\n') continue;
        
        line[strcspn(line, "\n")] = 0;  /* Supprimer le retour à la ligne */
        
        Backend *b = &backends[*count];
        memset(b, 0, sizeof(Backend));
        pthread_mutex_init(&b->lock, NULL);  /* Initialiser le mutex pour l'accès thread-safe */
        
        /* Parser les champs séparés par ':' */
        char *token = strtok(line, ":");
        if (token) strncpy(b->host, token, sizeof(b->host) - 1);  /* Champ 1 : hôte */
        
        token = strtok(NULL, ":");
        if (token) b->port = atoi(token);              /* Champ 2 : port */
        
        token = strtok(NULL, ":");
        if (token) b->weight = atoi(token);             /* Champ 3 : poids */
        
        token = strtok(NULL, ":");
        if (token) b->max_failures = atoi(token);       /* Champ 4 : échecs max */
        
        /* Initialiser l'état du backend */
        b->is_healthy = 1;           /* Considéré en bonne santé par défaut */
        b->failures = 0;             /* Aucun échec au départ */
        b->current_connections = 0;  /* Aucune connexion active */
        b->last_check = time(NULL);  /* Dernier check = maintenant */
        
        /* Valeurs par défaut si non spécifiées */
        if (b->weight <= 0) b->weight = 1;
        if (b->max_failures <= 0) b->max_failures = 3;
        
        (*count)++;
        
        log_message(LOG_INFO, "Loaded backend: %s:%d (weight: %d, max failures: %d)", 
                   b->host, b->port, b->weight, b->max_failures);
    }
    
    fclose(f);
    return backends;
}

/*
 * free_backends - Libère les ressources des backends
 * @backends: tableau de backends à libérer
 * @count: nombre de backends dans le tableau
 *
 * Détruit les mutex de chaque backend puis libère le tableau.
 */
void free_backends(Backend *backends, int count) {
    for (int i = 0; i < count; i++) {
        pthread_mutex_destroy(&backends[i].lock);
    }
    free(backends);
}

/*
 * increment_backend_connections - Incrémente le compteur de connexions d'un backend
 * @backend: le backend à modifier
 * Opération thread-safe protégée par le mutex du backend.
 */
void increment_backend_connections(Backend *backend) {
    pthread_mutex_lock(&backend->lock);
    backend->current_connections++;
    pthread_mutex_unlock(&backend->lock);
}

/*
 * decrement_backend_connections - Décrémente le compteur de connexions d'un backend
 * @backend: le backend à modifier
 * Vérifie que le compteur ne descend pas en dessous de 0.
 */
void decrement_backend_connections(Backend *backend) {
    pthread_mutex_lock(&backend->lock);
    if (backend->current_connections > 0) {
        backend->current_connections--;
    }
    pthread_mutex_unlock(&backend->lock);
}

/*
 * update_backend_health - Met à jour l'état de santé d'un backend
 * @backend: le backend à mettre à jour
 * @is_healthy: 1 si la connexion a réussi, 0 si elle a échoué
 *
 * Si la connexion réussit : remet le compteur d'échecs à 0 et marque le backend sain.
 * Si la connexion échoue : incrémente les échecs. Quand le nombre d'échecs atteint
 * max_failures, le backend est marqué comme non sain (hors ligne).
 */
void update_backend_health(Backend *backend, int is_healthy) {
    pthread_mutex_lock(&backend->lock);
    
    backend->last_check = time(NULL);
    
    if (is_healthy) {
        backend->failures = 0;  /* Remettre à zéro les échecs */
        if (!backend->is_healthy) {
            backend->is_healthy = 1;  /* Le backend revient en ligne */
            log_message(LOG_INFO, "Backend %s:%d is now HEALTHY", 
                       backend->host, backend->port);
        }
    } else {
        backend->failures++;
        /* Déclarer hors ligne si trop d'échecs consécutifs */
        if (backend->failures >= backend->max_failures && backend->is_healthy) {
            backend->is_healthy = 0;
            log_message(LOG_WARNING, "Backend %s:%d is now UNHEALTHY (%d failures)", 
                       backend->host, backend->port, backend->failures);
        }
    }
    
    pthread_mutex_unlock(&backend->lock);
}

/*
 * health_check_thread - Thread de vérification périodique de la santé des backends
 * @arg: pointeur vers une structure HealthArgs contenant la liste des backends
 * @return: NULL
 *
 * Boucle indéfiniment tant que 'running' est vrai :
 * 1. Pour chaque backend, tente d'ouvrir une connexion TCP
 * 2. Si la connexion réussit, le backend est marqué en bonne santé
 * 3. Si elle échoue, le compteur d'échecs est incrémenté
 * 4. Attend HEALTH_CHECK_INTERVAL secondes entre chaque cycle
 *
 * Le sleep est découpé en intervalles de 1 seconde pour réagir
 * rapidement à une demande d'arrêt du serveur.
 */
void* health_check_thread(void *arg) {
    typedef struct {
        Backend *backends;
        int count;
    } HealthArgs;
    HealthArgs *args = (HealthArgs *)arg;
    Backend *backends = args->backends;
    int count = args->count;
    
    log_message(LOG_INFO, "Health check thread started");
    
    extern volatile int running;  /* Variable globale d'état du serveur */
    while (running) {
        /* Vérifier chaque backend */
        for (int i = 0; i < count && running; i++) {
            Backend *b = &backends[i];
            
            /* Créer un socket TCP pour tester la connexion */
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                update_backend_health(b, 0);  /* Échec de création du socket */
                continue;
            }
            
            set_socket_timeout(sock, 2);  /* Timeout de 2 secondes pour le health check */
            
            /* Configurer l'adresse du backend */
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(b->port);
            
            int connected = 0;
            /* Essayer de se connecter en utilisant l'IP directe */
            if (inet_pton(AF_INET, b->host, &addr.sin_addr) > 0) {
                if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    connected = 1;  /* Connexion réussie */
                }
            } else {
                /* Sinon, résolution DNS */
                struct hostent *he = gethostbyname(b->host);
                if (he) {
                    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
                    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                        connected = 1;
                    }
                }
            }
            
            close(sock);
            update_backend_health(b, connected);  /* Mettre à jour l'état de santé */
        }
        
        /* Dormir par petits incréments de 1s pour réagir vite au shutdown */
        for (int s = 0; s < HEALTH_CHECK_INTERVAL && running; s++) {
            sleep(1);
        }
    }
    
    log_message(LOG_INFO, "Health check thread stopped");
    free(args);
    return NULL;
}

/*
 * get_total_backends_weight - Calcule le poids total des backends en bonne santé
 * @backends: tableau de backends
 * @count: nombre de backends
 * @return: somme des poids des backends sains
 *
 * Utilisé par l'algorithme de load balancing pondéré (Weighted Round Robin).
 */
int get_total_backends_weight(Backend *backends, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        if (backends[i].is_healthy) {
            total += backends[i].weight;
        }
    }
    return total;
}

/*
 * print_backend_stats - Affiche les statistiques de tous les backends
 * @backends: tableau de backends
 * @count: nombre de backends
 *
 * Affiche pour chaque backend : connexions actives, état de santé et poids.
 * Appelé lors de l'arrêt du serveur pour un résumé.
 */
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