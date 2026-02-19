/*
 * proxy.c - Fichier principal du reverse proxy HTTP
 * 
 * Ce programme implémente un serveur proxy inverse multi-threadé qui :
 * - Reçoit les requêtes HTTP des clients
 * - Sert les fichiers statiques (HTML, CSS, JS, images) et PHP localement
 * - Redirige les autres requêtes vers les serveurs backend
 * - Met en cache les réponses des backends selon des règles configurables
 * - Répartit la charge entre plusieurs backends (load balancing)
 * - Vérifie périodiquement la santé des backends (health checks)
 * - Protège contre les IP blacklistées et le flood (rate limiting)
 */

#include "config.h"
#include "logger.h"
#include "utils.h"
#include "backend_manager.h"
#include "cache.h"
#include "load_balancer.h"
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

/* === Variables globales === */
volatile int running = 1;                   /* Flag principal : 1 = serveur en marche, 0 = arrêt demandé */
static int server_port = 9999;              /* Port d'écoute du proxy (mis à jour dans main) */
static volatile int shutdown_requested = 0; /* Empêche les signaux multiples d'interférer */
static Cache *global_cache = NULL;          /* Cache HTTP partagé par tous les threads */
static CacheRules *global_cache_rules = NULL; /* Règles de cache chargées depuis le fichier de config */
static Backend *backends = NULL;            /* Tableau des serveurs backend */
static int backend_count = 0;              /* Nombre de backends actifs */
static LBStrategy lb_strategy = LB_ROUND_ROBIN; /* Stratégie de load balancing (par défaut : round robin) */
static int active_threads = 0;             /* Nombre de threads de traitement en cours */
static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER; /* Mutex pour protéger active_threads */

/*
 * signal_handler - Gestionnaire de signaux pour l'arrêt propre
 * @sig: numéro du signal reçu (SIGINT = Ctrl+C, SIGTERM = kill)
 *
 * Met running à 0 pour que la boucle principale s'arrête
 * et que le serveur se ferme proprement en libérant les ressources.
 */
void signal_handler(int sig) {
    if (!shutdown_requested) {
        log_message(LOG_INFO, "Received signal %d, requesting shutdown...", sig);
        shutdown_requested = 1;
        running = 0;
    }
}

/*
 * parse_http_request - Parse une requête HTTP brute en structure HttpRequest
 * @raw: la requête HTTP brute (chaîne de caractères)
 * @req: structure de sortie remplie avec les champs extraits
 * @return: 1 si succès, 0 si la requête est malformée
 *
 * Extrait :
 * - La méthode (GET, POST, etc.), le chemin et le protocole de la première ligne
 * - Les en-têtes HTTP (tout ce qui suit la première ligne)
 * - L'hôte et le port depuis l'en-tête Host
 */
int parse_http_request(const char *raw, HttpRequest *req) {
    memset(req, 0, sizeof(HttpRequest));  /* Initialiser tous les champs à zéro */
    
    /* Parser la première ligne : "GET /path HTTP/1.1" */
    int parsed = sscanf(raw, "%15s %1023s %15s", req->method, req->path, req->protocol);
    if (parsed != 3) {
        log_message(LOG_ERROR, "Failed to parse HTTP request line, parsed %d fields", parsed);
        log_message(LOG_DEBUG, "Raw request line: %.100s", raw);
        return 0;
    }
    
    log_message(LOG_DEBUG, "Parsed request: method='%s', path='%s', protocol='%s'", 
                req->method, req->path, req->protocol);
    
    /* Trouver le début des en-têtes (après la première ligne) */
    const char *headers_start = strstr(raw, "\r\n");
    if (!headers_start) {
        headers_start = strstr(raw, "\n");
        if (!headers_start) {
            log_message(LOG_ERROR, "No headers found in request");
            return 0;
        }
    }
    
    /* Trouver la fin des en-têtes (ligne vide = "\r\n\r\n") */
    const char *headers_end = strstr(headers_start + (headers_start[1] == '\n' ? 1 : 2), "\r\n\r\n");
    if (!headers_end) {
        headers_end = strstr(headers_start + (headers_start[1] == '\n' ? 1 : 2), "\n\n");
        if (!headers_end) {
            log_message(LOG_ERROR, "Incomplete headers in request");
            return 0;
        }
    }
    
    /* Copier les en-têtes dans la structure */
    size_t headers_len = headers_end - headers_start - 2;
    if (headers_len >= sizeof(req->headers) - 1) {
        log_message(LOG_ERROR, "Headers too long: %zu bytes", headers_len);
        return 0;
    }
    
    strncpy(req->headers, headers_start + 2, headers_len);
    req->headers[headers_len] = '\0';
    
    log_message(LOG_DEBUG, "Parsed headers (%zu bytes): %.200s", headers_len, req->headers);
    
    /* Extraire l'hôte et le port depuis l'en-tête "Host: hostname:port" */
    char *host_line = strstr(req->headers, "Host:");
    if (host_line) {
        char host_buffer[256];
        if (sscanf(host_line, "Host: %255[^\r\n]", host_buffer) == 1) {
            char *colon = strchr(host_buffer, ':');
            if (colon) {
                /* Host contient un port (ex: "localhost:8085") */
                *colon = '\0';
                strncpy(req->host, host_buffer, sizeof(req->host) - 1);
                req->host[sizeof(req->host) - 1] = '\0';
                req->port = atoi(colon + 1);
            } else {
                /* Host sans port (ex: "localhost"), défaut : 80 */
                strncpy(req->host, host_buffer, sizeof(req->host) - 1);
                req->host[sizeof(req->host) - 1] = '\0';
                req->port = 80;
            }
        }
    }
    
    return 1;
}

/*
 * serve_static - Sert un fichier statique au client
 * @client_sock: socket du client
 * @path: chemin relatif du fichier demandé (ex: "/index.html")
 *
 * 1. Vérifie la sécurité (bloque les tentatives de path traversal "../../etc/passwd")
 * 2. Ouvre le fichier depuis le dossier "web/"
 * 3. Détecte le type MIME selon l'extension (.html, .css, .js, .png, etc.)
 * 4. Envoie les en-têtes HTTP puis le contenu du fichier par blocs
 */
void serve_static(int client_sock, const char *path) {
    /* Sécurité : bloquer les tentatives d'accès à des fichiers hors du dossier web */
    if (strstr(path, "..") != NULL || strstr(path, "//") != NULL) {
        log_message(LOG_WARNING, "Path traversal attempt blocked: %s", path);
        send_http_response(client_sock, 403, "Forbidden", "text/plain", "Access denied");
        return;
    }
    
    /* Construire le chemin complet : "web" + chemin demandé */
    char full_path[2048];
    int path_len = snprintf(full_path, sizeof(full_path), "web%s", path);
    
    /* Vérifier que le chemin ne dépasse pas la taille du buffer */
    if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
        log_message(LOG_ERROR, "Path too long: %s", path);
        send_http_response(client_sock, 414, "URI Too Long", "text/plain", "Path too long");
        return;
    }
    
    /* Ouvrir le fichier en mode binaire (pour images, etc.) */
    FILE *file = fopen(full_path, "rb");
    if (!file) {
        log_message(LOG_ERROR, "Cannot open file: %s", full_path);
        send_http_response(client_sock, 404, "Not Found", "text/plain", "File not found");
        return;
    }
    
    /* Obtenir la taille du fichier */
    struct stat st;
    if (stat(full_path, &st) != 0) {
        log_message(LOG_ERROR, "Cannot stat file: %s", full_path);
        fclose(file);
        send_http_response(client_sock, 404, "Not Found", "text/plain", "File not found");
        return;
    }
    
    long file_size = st.st_size;
    log_message(LOG_DEBUG, "File size: %ld", file_size);
    
    /* Déterminer le type MIME selon l'extension du fichier */
    const char *content_type = "text/plain";     /* Type par défaut */
    if (strstr(full_path, ".html") || strstr(full_path, ".htm")) {
        content_type = "text/html";
    } else if (strstr(full_path, ".css")) {
        content_type = "text/css";
    } else if (strstr(full_path, ".js")) {
        content_type = "application/javascript";
    } else if (strstr(full_path, ".png")) {
        content_type = "image/png";
    } else if (strstr(full_path, ".jpg") || strstr(full_path, ".jpeg")) {
        content_type = "image/jpeg";
    } else if (strstr(full_path, ".gif")) {
        content_type = "image/gif";
    }
    
    /* Construire et envoyer les en-têtes HTTP */
    char headers[2048];
    int header_len = snprintf(headers, sizeof(headers), 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n", content_type, file_size);
    
    log_message(LOG_DEBUG, "header_len: %d", header_len);
    
    if (header_len < 0 || (size_t)header_len >= sizeof(headers)) {
        log_message(LOG_ERROR, "Header too long");
        fclose(file);
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "Header error");
        return;
    }
    
    /* Envoyer les en-têtes au client */
    log_message(LOG_DEBUG, "Sending headers: %.100s", headers);
    ssize_t sent = send(client_sock, headers, (size_t)header_len, 0);
    if (sent != header_len) {
        log_message(LOG_ERROR, "Failed to send headers");
        fclose(file);
        return;
    }
    
    /* Envoyer le contenu du fichier par blocs de BUFFER_SIZE octets */
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    size_t total_sent = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        log_message(LOG_DEBUG, "Read %zu bytes from file", bytes_read);
        sent = send(client_sock, buffer, bytes_read, 0);
        log_message(LOG_DEBUG, "Sent %zd bytes to client", sent);
        if (sent != (ssize_t)bytes_read) {
            log_message(LOG_ERROR, "Failed to send file data");
            break;
        }
        total_sent += sent;
    }
    
    log_message(LOG_DEBUG, "Total sent: %zu", total_sent);
    fclose(file);
}

/*
 * serve_php - Exécute un script PHP et envoie le résultat au client
 * @client_sock: socket du client
 * @path: chemin relatif du fichier PHP (ex: "/test.php")
 * @client_ip: adresse IP du client (non utilisée actuellement)
 *
 * 1. Vérifie la sécurité (path traversal)
 * 2. Vérifie que le fichier PHP existe
 * 3. Exécute le script via la commande "php -f" avec popen()
 * 4. Lit la sortie du script PHP
 * 5. Envoie le résultat comme réponse HTTP
 */
void serve_php(int client_sock, const char *path, const char *client_ip) {
    log_message(LOG_DEBUG, "Starting serve_php for path: %s", path);
    
    /* Sécurité : bloquer les tentatives de path traversal */
    if (strstr(path, "..") != NULL || strstr(path, "//") != NULL) {
        log_message(LOG_WARNING, "PHP path traversal attempt blocked: %s", path);
        send_http_response(client_sock, 403, "Forbidden", "text/plain", "Access denied");
        return;
    }
    
    /* Construire le chemin complet du fichier PHP */
    char full_path[2048];
    int path_len = snprintf(full_path, sizeof(full_path), "web%s", path);
    
    if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
        log_message(LOG_ERROR, "PHP path too long: %s", path);
        send_http_response(client_sock, 414, "URI Too Long", "text/plain", "Path too long");
        return;
    }
    
    log_message(LOG_DEBUG, "Full path: %s", full_path);
    
    /* Vérifier que le fichier PHP existe */
    struct stat st;
    if (stat(full_path, &st) != 0) {
        log_message(LOG_ERROR, "PHP file not found: %s", full_path);
        send_http_response(client_sock, 404, "Not Found", "text/plain", "PHP file not found");
        return;
    }
    
    /* Construire la commande PHP à exécuter avec les variables CGI */
    char command[4096];
    int cmd_len = snprintf(command, sizeof(command),
        "SERVER_ADDR=127.0.0.1 SERVER_PORT=%d REMOTE_ADDR=%s "
        "REQUEST_URI=%s SCRIPT_FILENAME=%s "
        "DOCUMENT_ROOT=web GATEWAY_INTERFACE=CGI/1.1 "
        "SERVER_SOFTWARE=ProxyReverse/1.0 "
        "php -f %s",
        server_port, client_ip ? client_ip : "127.0.0.1",
        path, full_path, full_path);
    
    if (cmd_len < 0 || (size_t)cmd_len >= sizeof(command)) {
        log_message(LOG_ERROR, "PHP command too long");
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "Command too long");
        return;
    }
    
    log_message(LOG_DEBUG, "PHP command: %s", command);
    
    /* Exécuter le script PHP via un processus enfant (pipe) */
    FILE *fp = popen(command, "r");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to popen PHP command");
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "PHP execution failed");
        return;
    }
    log_message(LOG_DEBUG, "popen successful");
    
    /* Lire l'intégralité de la sortie PHP dans un buffer dynamique */
    char buffer[BUFFER_SIZE];
    size_t total_size = 0;
    size_t capacity = BUFFER_SIZE * 4;    /* Capacité initiale : 32 Ko */
    char *output = malloc(capacity);
    if (!output) {
        log_message(LOG_ERROR, "Failed to malloc output buffer");
        pclose(fp);
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "Memory error");
        return;
    }
    output[0] = '\0';
    log_message(LOG_DEBUG, "Output buffer allocated");
    
    /* Lire la sortie ligne par ligne, agrandissant le buffer si nécessaire */
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t len = strlen(buffer);
        if (total_size + len + 1 > capacity) {
            capacity *= 2;  /* Doubler la capacité */
            char *new_output = realloc(output, capacity);
            if (!new_output) {
                log_message(LOG_ERROR, "Failed to realloc output buffer");
                free(output);
                pclose(fp);
                send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "Memory error");
                return;
            }
            output = new_output;
        }
        strcpy(output + total_size, buffer);
        total_size += len;
    }
    log_message(LOG_DEBUG, "Finished reading PHP output, total_size: %zu", total_size);
    
    /* Vérifier le code de retour du script PHP */
    int status = pclose(fp);
    log_message(LOG_DEBUG, "pclose status: %d", status);
    if (status != 0) {
        log_message(LOG_ERROR, "PHP script exited with status: %d", status);
        free(output);
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "PHP script error");
        return;
    }
    
    /* Construire et envoyer la réponse HTTP avec le contenu PHP */
    log_message(LOG_DEBUG, "Sending PHP response");
    
    char response[BUFFER_SIZE * 2];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", total_size, output);
    
    if (response_len < 0 || (size_t)response_len >= sizeof(response)) {
        log_message(LOG_ERROR, "Response too large");
        free(output);
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "Response too large");
        return;
    }
    
    int sent = send(client_sock, response, (size_t)response_len, 0);
    if (sent != response_len) {
        log_message(LOG_ERROR, "Failed to send PHP response: %d of %d bytes", sent, response_len);
    }
    
    free(output);
    log_message(LOG_DEBUG, "serve_php completed successfully");
}

/*
 * handle_client - Fonction principale de traitement d'une connexion client (exécutée dans un thread)
 * @arg: pointeur vers ClientArgs contenant le socket et les infos du client
 * @return: NULL
 *
 * Flux de traitement :
 * 1. Vérifier si l'IP est blacklistée
 * 2. Vérifier le rate limiting
 * 3. Lire et parser la requête HTTP
 * 4. Si le fichier existe localement : servir le fichier (statique ou PHP)
 * 5. Sinon, vérifier le cache et servir depuis le cache si disponible
 * 6. Sinon, sélectionner un backend via le load balancer et transférer la requête
 * 7. Mettre en cache la réponse du backend si applicable
 * 8. Nettoyer les ressources (sockets, mémoire)
 */
void* handle_client(void *arg) {
    ClientArgs *args = (ClientArgs *)arg;
    int client_sock = args->client_socket;
    char client_ip[INET_ADDRSTRLEN];
    strcpy(client_ip, args->client_ip);
    
    log_message(LOG_DEBUG, "Starting handle_client for %s", client_ip);
    
    /* === Étape 1 : Vérifier si l'IP est dans la liste noire === */
    if (is_blacklisted(client_ip)) {
        log_message(LOG_WARNING, "Blacklisted IP: %s", client_ip);
        send_http_response(client_sock, 403, "Forbidden", "text/plain", 
                          "Your IP has been blacklisted");
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    }
    
    /* === Étape 2 : Vérifier le rate limiting (anti-flood) === */
    if (!check_rate_limit(client_ip)) {
        log_message(LOG_WARNING, "Rate limit exceeded for IP: %s", client_ip);
        send_http_response(client_sock, 429, "Too Many Requests", "text/plain",
                          "Rate limit exceeded");
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    }
    
    /* === Étape 3 : Lire la requête HTTP du client === */
    char request_buffer[BUFFER_SIZE];
    int request_len = read_http_request(client_sock, request_buffer, sizeof(request_buffer));
    
    log_message(LOG_DEBUG, "Read %d bytes from client", request_len);
    
    if (request_len <= 0) {
        log_message(LOG_WARNING, "Failed to read request from %s", client_ip);
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    }
    
    log_message(LOG_DEBUG, "Raw request: %.100s", request_buffer);
    
    /* === Étape 4 : Parser la requête HTTP === */
    HttpRequest req;
    log_message(LOG_DEBUG, "About to parse HTTP request");
    if (!parse_http_request(request_buffer, &req)) {
        log_message(LOG_ERROR, "Failed to parse HTTP request from %s", client_ip);
        send_http_response(client_sock, 400, "Bad Request", "text/plain", 
                          "Malformed HTTP request");
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    }
    log_message(LOG_DEBUG, "HTTP request parsed successfully");
    
    // Simple test response
    // send_http_response(client_sock, 200, "OK", "text/plain", "Hello from proxy!");
    // close(client_sock);
    // free(args);
    
    // pthread_mutex_lock(&threads_mutex);
    // active_threads--;
    // pthread_mutex_unlock(&threads_mutex);
    
    // return NULL;
    
    log_message(LOG_INFO, "%s %s from %s", req.method, req.path, client_ip);
    
    /* === Étape 5 : Construire le chemin local du fichier demandé === */
    /* On préfixe le chemin de la requête avec "web/" pour chercher dans le dossier web/ */
    
    /* Extraire le chemin sans la query string (ex: "/index.html?t=123" → "/index.html") */
    char clean_path[1024];
    strncpy(clean_path, req.path, sizeof(clean_path) - 1);
    clean_path[sizeof(clean_path) - 1] = '\0';
    char *query = strchr(clean_path, '?');
    if (query) {
        *query = '\0';  /* Couper la query string */
    }
    
    char full_path[2048];  /* Buffer agrandi pour supporter les longs chemins */
    if (strcmp(clean_path, "/") == 0) {
        /* Si le chemin est "/", on sert index.html par défaut */
        strcpy(full_path, "web/index.html");
    } else {
        /* Sinon, on concatène "web" + le chemin sans query string */
        int path_len = snprintf(full_path, sizeof(full_path), "web%s", clean_path);
        if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
            /* Protection contre les chemins trop longs (dépassement de buffer) */
            log_message(LOG_ERROR, "Path too long: %s", req.path);
            send_http_response(client_sock, 414, "URI Too Long", "text/plain", "Path too long");
            close(client_sock);
            free(args);
            
            pthread_mutex_lock(&threads_mutex);
            active_threads--;
            pthread_mutex_unlock(&threads_mutex);
            
            return NULL;
        }
    }
    
    log_message(LOG_DEBUG, "Full path: %s", full_path);
    
    /* === Étape 6 : Vérifier si le fichier existe localement === */
    /* Si le fichier existe, on le sert directement sans passer par un backend */
    struct stat st;
    if (stat(full_path, &st) == 0) {
        log_message(LOG_DEBUG, "File exists, serving %s", full_path);
        if (strstr(clean_path, ".php") != NULL) {
            /* Les fichiers PHP sont exécutés via PHP-CGI */
            serve_php(client_sock, clean_path, client_ip);
        } else {
            /* Les autres fichiers sont servis en tant que contenu statique */
            const char *serve_path = (strcmp(clean_path, "/") == 0) ? "/index.html" : clean_path;
            serve_static(client_sock, serve_path);
        }
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    } else {
        log_message(LOG_DEBUG, "stat failed for %s: %s", full_path, strerror(errno));
    }
    
    /* Le fichier n'existe pas localement → on transfère vers un backend */
    log_message(LOG_DEBUG, "File not found locally, trying backend for: %s", req.path);
    
    /* === Étape 7 : Vérifier le cache pour cette requête === */
    /* On détermine si la requête est éligible au cache selon les règles configurées */
    int cache_max_age = 0;       /* Durée de vie maximale en secondes dans le cache */
    size_t cache_max_size = 0;   /* Taille maximale de la réponse à mettre en cache */
    int should_cache = should_cache_request(request_buffer) && 
                      cache_rules_match(global_cache_rules, req.path, &cache_max_age, &cache_max_size);
    
    log_message(LOG_DEBUG, "Cache check for %s: should_cache=%d, max_age=%d, max_size=%zu", 
                req.path, should_cache, cache_max_age, cache_max_size);
    
    /* Si la requête est éligible au cache, chercher dans le cache */
    if (should_cache && cache_max_age > 0) {
        /* Construire la clé de cache : méthode + chemin + en-têtes */
        char cache_key[CACHE_KEY_SIZE];
        snprintf(cache_key, sizeof(cache_key), "%s %s %s", req.method, req.path, req.headers);
        
        /* Chercher la réponse dans le cache */
        char *cached_response = cache_get(global_cache, cache_key);
        if (cached_response) {
            /* Cache HIT : envoyer directement la réponse en cache sans contacter le backend */
            log_message(LOG_INFO, "Serving from cache: %s", req.path);
            int sent = send(client_sock, cached_response, strlen(cached_response), 0);
            if (sent <= 0) {
                log_message(LOG_ERROR, "Failed to send cached response");
            }
            free(cached_response);
            close(client_sock);
            free(args);
            
            pthread_mutex_lock(&threads_mutex);
            active_threads--;
            pthread_mutex_unlock(&threads_mutex);
            
            return NULL;
        }
    }
    
    /* === Étape 8 : Sélectionner un backend via le load balancer === */
    /* Cache MISS ou requête non-cacheable : on doit contacter un backend */
    Backend *backend = select_backend(args->backends, args->backend_count, 
                                     lb_strategy, client_ip);
    
    if (!backend) {
        /* Aucun backend disponible (tous en panne) */
        log_message(LOG_ERROR, "No backend selected!");
        send_http_response(client_sock, 503, "Service Unavailable", "text/plain", 
                          "No backend available");
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    }
    
    log_message(LOG_INFO, "Forwarding to backend: %s:%d", backend->host, backend->port);
    
    /* === Étape 9 : Se connecter au backend et transférer la requête === */
    int backend_sock = connect_to_backend(backend->host, backend->port);
    if (backend_sock < 0) {
        /* Échec de connexion → marquer le backend comme indisponible */
        log_message(LOG_ERROR, "Failed to connect to backend %s:%d", 
                   backend->host, backend->port);
        update_backend_health(backend, 0);
        send_http_response(client_sock, 502, "Bad Gateway", "text/plain",
                          "Cannot connect to backend server");
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    }
    
    /* Envoyer la requête HTTP originale au backend */
    if (send(backend_sock, request_buffer, (size_t)request_len, 0) != request_len) {
        /* Échec d'envoi de la requête au backend */
        log_message(LOG_ERROR, "Failed to send request to backend");
        update_backend_health(backend, 0);
        close(backend_sock);
        close(client_sock);
        free(args);
        
        pthread_mutex_lock(&threads_mutex);
        active_threads--;
        pthread_mutex_unlock(&threads_mutex);
        
        return NULL;
    }
    
    /* === Étape 10 : Relayer la réponse du backend vers le client === */
    /* On lit la réponse du backend par morceaux et on la renvoie au client */
    char response_buffer[BUFFER_SIZE];
    int total_response_size = 0;   /* Taille totale accumulée de la réponse */
    char *full_response = NULL;    /* Buffer pour accumuler la réponse complète (pour le cache) */
    int can_cache_response = should_cache_request(request_buffer) && should_cache;
    
    /* Boucle de lecture : lire depuis le backend et renvoyer au client */
    while (1) {
        int bytes = recv(backend_sock, response_buffer, sizeof(response_buffer) - 1, 0);
        
        if (bytes <= 0) {
            break;  /* Fin de la réponse ou erreur */
        }
        
        /* Renvoyer les données reçues au client */
        int sent = send(client_sock, response_buffer, (size_t)bytes, 0);
        if (sent != bytes) {
            log_message(LOG_WARNING, "Failed to send all data to client: %d of %d bytes", 
                       sent, bytes);
            break;
        }
        
        /* Si la réponse est éligible au cache, accumuler les données */
        if (can_cache_response && (size_t)total_response_size + (size_t)bytes <= cache_max_size) {
            /* Agrandir le buffer de réponse complète (realloc dynamique) */
            char *new_full_response = realloc(full_response, (size_t)total_response_size + (size_t)bytes + 1);
            if (!new_full_response) {
                /* Échec d'allocation → abandonner la mise en cache */
                log_message(LOG_ERROR, "Failed to realloc for caching");
                free(full_response);
                full_response = NULL;
                can_cache_response = 0;
            } else {
                full_response = new_full_response;
                /* Copier le nouveau morceau à la suite du buffer */
                memcpy(full_response + total_response_size, response_buffer, (size_t)bytes);
                total_response_size += bytes;
            }
        }
    }
    
    /* === Étape 11 : Mettre en cache la réponse si applicable === */
    if (can_cache_response && full_response && total_response_size > 0 && 
        (size_t)total_response_size <= cache_max_size) {
        full_response[total_response_size] = '\0';  /* Terminer la chaîne */
        
        /* Vérifier que la réponse HTTP est éligible au cache (code 200, etc.) */
        if (should_cache_response(full_response)) {
            char cache_key[CACHE_KEY_SIZE];
            snprintf(cache_key, sizeof(cache_key), "%s %s %s", req.method, req.path, req.headers);
            
            /* Calculer la date d'expiration du cache */
            time_t expiry = time(NULL) + cache_max_age;
            /* Vérifier si les en-têtes HTTP spécifient une expiration plus courte */
            time_t header_expiry = get_cache_expiry_from_headers(full_response);
            if (header_expiry > 0 && header_expiry < expiry) {
                expiry = header_expiry;  /* Utiliser l'expiration la plus courte */
            }
            
            /* Stocker la réponse dans le cache LRU */
            cache_put(global_cache, cache_key, full_response, (size_t)total_response_size, expiry);
            
            log_message(LOG_INFO, "Cached response for: %s (size: %d, expires in %ld seconds)", 
                       req.path, total_response_size, expiry - time(NULL));
        }
    }
    
    /* Libérer le buffer de réponse complète */
    if (full_response) {
        free(full_response);
    }
    
    /* === Étape 12 : Nettoyage final === */
    update_backend_health(backend, 1);        /* Marquer le backend comme sain (réponse reçue) */
    decrement_backend_connections(backend);    /* Décrémenter le compteur de connexions actives */
    close(backend_sock);                      /* Fermer la connexion vers le backend */
    close(client_sock);                       /* Fermer la connexion vers le client */
    
    log_message(LOG_INFO, "Connection closed for %s", client_ip);
    free(args);  /* Libérer la structure d'arguments du thread */
    
    /* Décrémenter le nombre de threads actifs (protégé par mutex) */
    pthread_mutex_lock(&threads_mutex);
    active_threads--;
    pthread_mutex_unlock(&threads_mutex);
    
    return NULL;
}

/*
 * main - Point d'entrée du programme proxy inverse
 * @argc: nombre d'arguments en ligne de commande
 * @argv: tableau des arguments
 *
 * Arguments supportés :
 *   -p <port>     : port d'écoute du proxy (défaut: 9999)
 *   -c <fichier>  : fichier de configuration des backends (défaut: config/backends.cfg)
 *   -s <stratégie>: stratégie de load balancing (0=RoundRobin, 1=LeastConn, 2=IPHash, 3=WeightedRR)
 *
 * Séquence de démarrage :
 * 1. Parser les arguments CLI
 * 2. Initialiser le logger
 * 3. Configurer les gestionnaires de signaux
 * 4. Charger les backends
 * 5. Initialiser le cache et ses règles
 * 6. Lancer le thread de health check
 * 7. Créer le socket serveur et entrer dans la boucle d'acceptation
 */
int main(int argc, char *argv[]) {
    int proxy_port = 9999;                     /* Port d'écoute par défaut */
    /* server_port sera mis à jour après parsing des arguments */
    char *config_file = "config/backends.cfg"; /* Fichier de config des backends par défaut */
    
    /* --- Parsing des arguments de la ligne de commande --- */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            proxy_port = atoi(argv[++i]);   /* -p : définir le port du proxy */
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_file = argv[++i];        /* -c : définir le fichier de config */
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            lb_strategy = atoi(argv[++i]);  /* -s : définir la stratégie de load balancing */
        }
    }
    
    /* Synchroniser le port global pour serve_php */
    server_port = proxy_port;
    
    /* --- Initialisation du système de logging --- */
    init_logger("proxy.log");
    log_message(LOG_INFO, "Starting reverse proxy on port %d", proxy_port);
    
    /* --- Configuration des handlers de signaux pour un arrêt propre --- */
    signal(SIGINT, signal_handler);    /* Ctrl+C → arrêt propre */
    signal(SIGTERM, signal_handler);   /* kill → arrêt propre */
    signal(SIGPIPE, SIG_IGN);         /* Ignorer SIGPIPE pour éviter crash sur écriture socket fermée */
    
    /* --- Chargement des serveurs backend depuis le fichier de configuration --- */
    backends = load_backends(config_file, &backend_count);
    if (!backends || backend_count == 0) {
        log_message(LOG_ERROR, "No backends loaded from %s", config_file);
        
        /* Créer un backend par défaut pour les tests si aucun n'est configuré */
        log_message(LOG_INFO, "Creating default backend for testing");
        backend_count = 1;
        backends = malloc(sizeof(Backend) * backend_count);
        if (backends) {
            Backend *b = &backends[0];
            memset(b, 0, sizeof(Backend));
            strcpy(b->host, "127.0.0.1");
            b->port = 8081;
            b->weight = 1;
            b->max_failures = 5;
            b->is_healthy = 1;
            b->failures = 0;
            b->current_connections = 0;
            b->last_check = time(NULL);
            pthread_mutex_init(&b->lock, NULL);
            log_message(LOG_INFO, "Default backend: %s:%d", b->host, b->port);
        }
    }
    
    /* Vérification finale : si aucun backend n'est disponible, arrêter */
    if (!backends) {
        log_message(LOG_ERROR, "Failed to initialize backends");
        close_logger();
        return 1;
    }
    
    /* --- Initialisation du cache LRU --- */
    global_cache = cache_init(CACHE_CAPACITY);
    
    /* --- Chargement des règles de cache depuis le fichier de configuration --- */
    global_cache_rules = cache_rules_init();
    if (!cache_rules_load(global_cache_rules, "config/cache_rules.cfg")) {
        log_message(LOG_WARNING, "Failed to load cache rules, using default behavior");
    }
    
    /* --- Création et lancement du thread de health check --- */
    /* Ce thread vérifie périodiquement la disponibilité de chaque backend */
    pthread_t health_thread;
    typedef struct {
        Backend *backends;  /* Tableau de backends à vérifier */
        int count;          /* Nombre de backends */
    } HealthArgs;
    HealthArgs *thread_args = malloc(sizeof(HealthArgs));
    if (!thread_args) {
        log_message(LOG_ERROR, "Failed to allocate health thread args");
    } else {
        thread_args->backends = backends;
        thread_args->count = backend_count;
        
        if (pthread_create(&health_thread, NULL, health_check_thread, thread_args) != 0) {
            log_message(LOG_ERROR, "Failed to create health check thread");
            free(thread_args);
        } else {
            /* Détacher le thread : il s'exécutera en arrière-plan */
            pthread_detach(health_thread);
        }
    }
    
    /* --- Création du socket serveur d'écoute --- */
    int server_sock = create_server_socket(proxy_port);
    if (server_sock < 0) {
        log_message(LOG_ERROR, "Failed to create server socket");
        close_logger();
        return 1;
    }
    
    log_message(LOG_INFO, "Proxy server ready. Press Ctrl+C to stop.");
    
    /* =====================================================
     *   BOUCLE PRINCIPALE D'ACCEPTATION DES CONNEXIONS
     * =====================================================
     * Le proxy attend les connexions entrantes et crée un
     * thread dédié pour chaque client connecté.
     */
    while (running) {
        log_message(LOG_DEBUG, "Waiting for connection, running=%d, active_threads=%d", 
                   running, active_threads);
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        /* Accepter une nouvelle connexion client (bloquant) */
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (running) {
                log_message(LOG_ERROR, "Accept failed: %s", strerror(errno));
            }
            continue;  /* Ignorer l'erreur et réessayer */
        }
        
        /* Vérifier si on n'a pas atteint le nombre max de threads actifs */
        pthread_mutex_lock(&threads_mutex);
        if (active_threads >= MAX_CLIENTS) {
            log_message(LOG_WARNING, "Too many active threads, rejecting connection");
            close(client_sock);
            pthread_mutex_unlock(&threads_mutex);
            continue;  /* Rejeter la connexion et attendre la suivante */
        }
        active_threads++;  /* Réserver un slot pour ce nouveau thread */
        pthread_mutex_unlock(&threads_mutex);
        
        /* Préparer les arguments pour le thread client */
        ClientArgs *args = malloc(sizeof(ClientArgs));
        if (!args) {
            log_message(LOG_ERROR, "Failed to allocate client args");
            close(client_sock);
            
            pthread_mutex_lock(&threads_mutex);
            active_threads--;  /* Libérer le slot réservé */
            pthread_mutex_unlock(&threads_mutex);
            
            continue;
        }
        
        /* Remplir la structure d'arguments du thread */
        args->client_socket = client_sock;
        args->client_addr = client_addr;
        args->backends = backends;
        args->backend_count = backend_count;
        args->cache = global_cache;
        inet_ntop(AF_INET, &client_addr.sin_addr, args->client_ip, INET_ADDRSTRLEN);
        
        /* Créer un thread dédié pour traiter cette connexion */
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client, args) != 0) {
            log_message(LOG_ERROR, "Failed to create client thread");
            close(client_sock);
            free(args);
            
            pthread_mutex_lock(&threads_mutex);
            active_threads--;
            pthread_mutex_unlock(&threads_mutex);
        } else {
            /* Détacher le thread : il se nettoiera automatiquement à sa fin */
            pthread_detach(client_thread);
        }
    }
    
    /* =====================================================
     *   SÉQUENCE D'ARRÊT PROPRE DU PROXY
     * =====================================================
     * Exécutée quand running passe à 0 (signal SIGINT/SIGTERM)
     */
    log_message(LOG_INFO, "Shutting down...");
    
    /* Fermer le socket serveur (arrêter d'accepter de nouvelles connexions) */
    close(server_sock);
    
    /* Afficher les statistiques et libérer les backends */
    if (backends) {
        print_backend_stats(backends, backend_count);
        free_backends(backends, backend_count);
    }
    
    /* Afficher les statistiques du cache et le libérer */
    if (global_cache) {
        cache_print_stats(global_cache);
        cache_free(global_cache);
    }
    
    /* Libérer les règles de cache */
    if (global_cache_rules) {
        cache_rules_free(global_cache_rules);
    }
    
    /* Fermer le fichier de log */
    close_logger();
    
    log_message(LOG_INFO, "Proxy server stopped");
    
    return 0;  /* Fin du programme */
}