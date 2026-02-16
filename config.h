/*
 * config.h - Fichier de configuration principal du reverse proxy
 * Contient toutes les constantes, structures de données et déclarations
 * utilisées dans l'ensemble du projet.
 */

#ifndef CONFIG_H
#define CONFIG_H

/* === Inclusions des bibliothèques standard nécessaires === */
#include <stdio.h>       /* Entrées/sorties standard (printf, fopen, etc.) */
#include <stdlib.h>      /* Fonctions utilitaires (malloc, free, atoi, etc.) */
#include <string.h>      /* Manipulation de chaînes (strcpy, strcmp, strlen, etc.) */
#include <time.h>        /* Fonctions de gestion du temps (time, localtime, etc.) */
#include <pthread.h>     /* Threads POSIX pour le multi-threading */
#include <unistd.h>      /* Appels système POSIX (close, sleep, etc.) */
#include <sys/socket.h>  /* API socket (socket, bind, listen, accept, etc.) */
#include <netinet/in.h>  /* Structures d'adresses Internet (sockaddr_in, etc.) */
#include <arpa/inet.h>   /* Conversion d'adresses IP (inet_pton, inet_ntop, etc.) */
#include <sys/types.h>   /* Types de données système */
#include <sys/stat.h>    /* Informations sur les fichiers (stat) */
#include <fcntl.h>       /* Contrôle de fichiers (open, fcntl) */
#include <errno.h>       /* Gestion des codes d'erreur */
#include <signal.h>      /* Gestion des signaux (SIGINT, SIGTERM, etc.) */

/* === Constantes de configuration du serveur === */
#define MAX_BACKENDS 10                     /* Nombre maximum de serveurs backend supportés */
#define MAX_CLIENTS 100                     /* Nombre maximum de connexions clients simultanées */
#define BUFFER_SIZE 8192                    /* Taille du buffer de lecture/écriture (8 Ko) */
#define CACHE_CAPACITY 100                  /* Nombre maximum d'entrées dans le cache */
#define MAX_CACHE_ENTRY_SIZE (10 * 1024 * 1024) /* Taille max d'une entrée de cache (10 Mo) */
#define CACHE_KEY_SIZE 8192                 /* Taille max d'une clé de cache */
#define HEALTH_CHECK_INTERVAL 10            /* Intervalle de vérification santé des backends (en secondes) */
#define REQUEST_TIMEOUT 30                  /* Timeout pour les requêtes HTTP (en secondes) */

/*
 * LogLevel - Niveaux de journalisation
 * Permet de filtrer les messages de log par sévérité.
 * DEBUG < INFO < WARNING < ERROR
 */
typedef enum {
    LOG_DEBUG,      /* Messages de débogage détaillés */
    LOG_INFO,       /* Messages d'information générale */
    LOG_WARNING,    /* Avertissements (problèmes non critiques) */
    LOG_ERROR       /* Erreurs critiques */
} LogLevel;

/*
 * Backend - Représente un serveur backend
 * Chaque backend est un serveur vers lequel le proxy peut rediriger les requêtes.
 * Contient les informations de connexion, l'état de santé et les statistiques.
 */
typedef struct {
    char host[256];           /* Adresse IP ou nom d'hôte du backend */
    int port;                 /* Port d'écoute du backend */
    int weight;               /* Poids pour le load balancing pondéré (plus élevé = plus de trafic) */
    int current_connections;  /* Nombre de connexions actives vers ce backend */
    int is_healthy;           /* État de santé : 1 = en ligne, 0 = hors ligne */
    time_t last_check;        /* Timestamp de la dernière vérification de santé */
    int failures;             /* Compteur d'échecs consécutifs */
    int max_failures;         /* Nombre max d'échecs avant de déclarer le backend hors ligne */
    pthread_mutex_t lock;     /* Mutex pour l'accès thread-safe aux données du backend */
} Backend;

/*
 * CacheEntry - Entrée individuelle dans le cache
 * Stocke une réponse HTTP mise en cache avec ses métadonnées.
 * Utilise une structure de liste doublement chaînée pour l'algorithme LRU.
 */
struct CacheEntry {
    char key[512];              /* Clé d'identification de l'entrée (méthode + chemin + headers) */
    char *data;                 /* Données de la réponse mise en cache */
    size_t size;                /* Taille des données en octets */
    time_t timestamp;           /* Date de création de l'entrée */
    time_t expiry;              /* Date d'expiration de l'entrée */
    struct CacheEntry *next;    /* Pointeur vers l'entrée suivante (pour la liste chaînée) */
    struct CacheEntry *prev;    /* Pointeur vers l'entrée précédente (pour la liste LRU) */
    char hash_key[65];          /* Hash SHA-256 du contenu (pour vérifier l'intégrité) */
};

typedef struct CacheEntry CacheEntry;

/*
 * Cache - Structure principale du système de cache
 * Implémente un cache LRU (Least Recently Used) avec des buckets hash
 * pour un accès rapide aux entrées.
 */
typedef struct {
    CacheEntry **buckets;       /* Tableau de buckets pour le hachage (table de hachage) */
    int capacity;               /* Capacité maximale en nombre d'entrées */
    int count;                  /* Nombre actuel d'entrées dans le cache */
    CacheEntry *lru_head;       /* Tête de la liste LRU (élément le plus récemment utilisé) */
    CacheEntry *lru_tail;       /* Queue de la liste LRU (élément le moins récemment utilisé) */
    pthread_mutex_t lock;       /* Mutex pour l'accès thread-safe au cache */
    size_t total_size;          /* Taille totale des données stockées en octets */
} Cache;

/*
 * CacheRule - Règle de mise en cache
 * Définit les paramètres de cache pour un patron d'URL donné.
 */
typedef struct {
    char pattern[256];  /* Patron d'URL (ex: "*.html", "/api/...") */
    int max_age;        /* Durée de vie max en secondes */
    size_t max_size;    /* Taille max de la réponse cacheable en octets */
} CacheRule;

/*
 * CacheRules - Collection de règles de cache
 * Tableau dynamique contenant toutes les règles de mise en cache
 * chargées depuis le fichier de configuration.
 */
typedef struct {
    CacheRule *rules;   /* Tableau dynamique de règles */
    int count;          /* Nombre de règles chargées */
    int capacity;       /* Capacité allouée du tableau */
} CacheRules;

/*
 * ClientArgs - Arguments passés au thread de gestion d'un client
 * Contient toutes les informations nécessaires pour traiter
 * une connexion client dans un thread séparé.
 */
typedef struct {
    int client_socket;              /* Socket de communication avec le client */
    struct sockaddr_in client_addr; /* Adresse réseau du client */
    Backend *backends;              /* Tableau des backends disponibles */
    int backend_count;              /* Nombre de backends */
    Cache *cache;                   /* Pointeur vers le cache global */
    char client_ip[INET_ADDRSTRLEN]; /* Adresse IP du client en format texte */
} ClientArgs;

/*
 * HttpRequest - Requête HTTP parsée
 * Contient les champs extraits d'une requête HTTP brute
 * après le parsing de la première ligne et des en-têtes.
 */
typedef struct {
    char method[16];      /* Méthode HTTP (GET, POST, PUT, DELETE, etc.) */
    char path[1024];      /* Chemin de la ressource demandée (ex: "/index.html") */
    char protocol[16];    /* Version du protocole (ex: "HTTP/1.1") */
    char host[256];       /* Nom d'hôte extrait de l'en-tête Host */
    int port;             /* Port extrait de l'en-tête Host (défaut: 80) */
    char headers[4096];   /* En-têtes HTTP bruts */
} HttpRequest;

/*
 * LBStrategy - Stratégie de répartition de charge (Load Balancing)
 * Détermine comment le proxy sélectionne le backend pour chaque requête.
 */
typedef enum {
    LB_ROUND_ROBIN,             /* Tour à tour : chaque backend reçoit une requête à son tour */
    LB_LEAST_CONNECTIONS,       /* Moins de connexions : envoie vers le backend le moins chargé */
    LB_IP_HASH,                 /* Hash IP : même client -> même backend (affinité de session) */
    LB_WEIGHTED_ROUND_ROBIN     /* Round-robin pondéré : prend en compte le poids de chaque backend */
} LBStrategy;

/* === Déclarations de fonctions globales === */
void log_message(LogLevel level, const char *format, ...);  /* Écrire un message dans le journal */
char* get_client_ip(struct sockaddr_in addr);                /* Obtenir l'IP du client en format texte */
int parse_http_request(const char *raw, HttpRequest *req);   /* Parser une requête HTTP brute */
int should_cache_response(const char *response);             /* Vérifier si une réponse doit être cachée */
time_t get_cache_expiry(const char *headers);                /* Calculer la date d'expiration du cache */
char* generate_etag(const char *data, size_t size);          /* Générer un ETag pour le contenu */

#endif