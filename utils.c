/*
 * utils.c - Fonctions utilitaires du reverse proxy
 * Contient les fonctions réseau (création de sockets, connexions),
 * les fonctions de sécurité (blacklist, rate limiting),
 * et les fonctions de manipulation de données (hash, pattern matching, URL decode).
 */

#include "utils.h"
#include "logger.h"
#include <ctype.h>       /* Pour tolower(), isxdigit() */
#include <sys/time.h>    /* Pour gettimeofday() */
#include <netdb.h>       /* Pour gethostbyname() - résolution DNS */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * create_server_socket - Crée et configure un socket serveur TCP
 * @port: numéro de port sur lequel écouter
 * @return: descripteur du socket, ou -1 en cas d'erreur 
 *
 * Étapes :
 * 1. Crée un socket TCP (SOCK_STREAM)
 * 2. Active SO_REUSEADDR pour pouvoir réutiliser le port immédiatement
 * 3. Active SO_REUSEPORT si disponible (permet plusieurs processus sur le même port)
 * 4. Lie le socket à toutes les interfaces (INADDR_ANY) sur le port donné
 * 5. Met le socket en mode écoute avec MAX_CLIENTS connexions en attente
 */
int create_server_socket(int port) {
    /* Créer un socket TCP */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_message(LOG_ERROR, "Cannot create socket: %s", strerror(errno));
        return -1;
    }
    
    /* Permettre la réutilisation immédiate du port après fermeture */
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(LOG_ERROR, "Cannot set SO_REUSEADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Permettre à plusieurs processus d'écouter sur le même port (si supporté) */
    #ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        log_message(LOG_WARNING, "Cannot set SO_REUSEPORT: %s", strerror(errno));
    }
    #endif
    
    /* Configurer l'adresse d'écoute : toutes les interfaces, port spécifié */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;          /* IPv4 */
    addr.sin_addr.s_addr = INADDR_ANY;  /* Écouter sur toutes les interfaces réseau */
    addr.sin_port = htons(port);         /* Convertir le port en ordre réseau (big-endian) */
    
    /* Lier le socket à l'adresse */
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message(LOG_ERROR, "Cannot bind socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Mettre le socket en mode écoute */
    if (listen(sock, MAX_CLIENTS) < 0) {
        log_message(LOG_ERROR, "Cannot listen on socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    log_message(LOG_INFO, "Server listening on port %d", port);
    return sock;
}

/*
 * connect_to_backend - Établit une connexion TCP vers un serveur backend
 * @host: adresse IP ou nom d'hôte du backend
 * @port: port du backend
 * @return: descripteur du socket connecté, ou -1 en cas d'erreur
 *
 * Tente d'abord de convertir l'adresse comme IP directe (inet_pton),
 * puis fait une résolution DNS (gethostbyname) si nécessaire.
 */
int connect_to_backend(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    set_socket_timeout(sock, 5);  /* Timeout de 5 secondes pour la connexion */
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    /* Essayer de convertir l'adresse comme IP (ex: "127.0.0.1") */
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        /* Si ce n'est pas une IP, faire une résolution DNS */
        struct hostent *he = gethostbyname(host);
        if (he == NULL) {
            close(sock);
            return -1;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    /* Se connecter au backend */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

/*
 * send_http_response - Envoie une réponse HTTP complète au client
 * @sock: socket du client
 * @status_code: code HTTP (200, 404, 500, etc.)
 * @message: message associé au code ("OK", "Not Found", etc.)
 * @content_type: type MIME du contenu ("text/html", "text/plain", etc.)
 * @body: corps de la réponse (peut être NULL)
 *
 * Construit la réponse HTTP avec les en-têtes appropriés,
 * puis ferme le côté écriture du socket pour signaler la fin.
 */
void send_http_response(int sock, int status_code, const char *message, 
                        const char *content_type, const char *body) {
    char response[BUFFER_SIZE];
    int length = 0;
    
    /* Construire la réponse avec ou sans body */
    if (body) {
        length = snprintf(response, BUFFER_SIZE,
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            status_code, message, content_type, strlen(body), body);
    } else {
        length = snprintf(response, BUFFER_SIZE,
            "HTTP/1.1 %d %s\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            status_code, message);
    }
    
    /* Vérifier que la réponse tient dans le buffer */
    if (length < 0 || length >= BUFFER_SIZE) {
        log_message(LOG_ERROR, "Response too large: %d bytes", length);
        return;
    }
    
    log_message(LOG_DEBUG, "Sending HTTP response: %d %s, length: %d", status_code, message, length);
    log_message(LOG_DEBUG, "Response headers: %.200s", response);
    
    /* Envoyer la réponse au client */
    int sent = send(sock, response, length, 0);
    log_message(LOG_DEBUG, "send() returned: %d", sent);
    if (sent < 0) {
        log_message(LOG_ERROR, "send() failed: %s", strerror(errno));
    }
    
    /* Fermer le côté écriture pour signaler la fin de la réponse au client */
    shutdown(sock, SHUT_WR);
    usleep(100000);  /* Attendre 100ms pour que les données soient envoyées */
}

/*
 * read_http_request - Lit une requête HTTP depuis un socket
 * @sock: socket du client
 * @buffer: buffer de réception
 * @size: taille du buffer
 * @return: nombre d'octets lus, ou 0/négatif en cas d'erreur
 *
 * Lit les données en boucle jusqu'à trouver la fin des en-têtes HTTP
 * (séquence "\r\n\r\n" ou "\n\n") ou jusqu'au timeout.
 */
int read_http_request(int sock, char *buffer, int size) {
    int total_read = 0;
    int bytes_read;
    
    set_socket_timeout(sock, REQUEST_TIMEOUT);  /* Appliquer le timeout de lecture */
    
    while (total_read < size - 1) {
        /* Lire les données disponibles sur le socket */
        bytes_read = recv(sock, buffer + total_read, size - total_read - 1, 0);
        
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                log_message(LOG_DEBUG, "Client disconnected");  /* Client a fermé la connexion */
            } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
                log_message(LOG_ERROR, "Error reading from socket: %s", strerror(errno));
            }
            break;
        }
        
        total_read += bytes_read;
        buffer[total_read] = '\0';
        
        /* Vérifier si on a reçu la fin des en-têtes HTTP */
        if (strstr(buffer, "\r\n\r\n") != NULL || strstr(buffer, "\n\n") != NULL) {
            break;  /* Requête complète reçue */
        }
    }
    
    buffer[total_read] = '\0';
    return total_read;
}

/*
 * forward_data - Transfère des données d'un socket source vers un socket destination
 * @from_sock: socket source (d'où lire)
 * @to_sock: socket destination (où écrire)
 * @buffer: buffer temporaire pour le transfert
 * @size: taille du buffer
 * @return: nombre d'octets transférés, 0 si déconnexion, -1 si erreur
 *
 * Lit un bloc de données depuis from_sock et l'envoie à to_sock.
 * Utilisé pour relayer les données entre le client et le backend.
 */
int forward_data(int from_sock, int to_sock, char *buffer, int size) {
    int bytes_read = recv(from_sock, buffer, size, 0);
    if (bytes_read <= 0) {
        return bytes_read;  /* 0 = déconnexion, < 0 = erreur */
    }
    
    int bytes_sent = send(to_sock, buffer, bytes_read, 0);
    if (bytes_sent != bytes_read) {
        log_message(LOG_ERROR, "Failed to forward all data: %d of %d bytes", bytes_sent, bytes_read);
        return -1;
    }
    
    return bytes_read;
}

/*
 * is_blacklisted - Vérifie si une IP est dans la liste noire
 * @ip: adresse IP à vérifier
 * @return: 1 si l'IP est bloquée, 0 sinon
 *
 * Lit le fichier config/blacklist.txt à chaque appel et compare
 * l'IP avec chaque entrée. Les lignes commençant par '#' sont ignorées.
 * L'accès au fichier est protégé par un mutex pour être thread-safe.
 */
int is_blacklisted(const char *ip) {
    static pthread_mutex_t bl_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_mutex_lock(&bl_mutex);
    FILE *f = fopen("config/blacklist.txt", "r");
    if (!f) {
        pthread_mutex_unlock(&bl_mutex);
        return 0;  /* Pas de fichier = pas de blocage */
    }
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;    /* Supprimer le retour à la ligne */
        line[strcspn(line, "\r")] = 0;    /* Supprimer aussi le retour chariot */
        if (line[0] == '#' || line[0] == '\0') continue;  /* Ignorer commentaires et lignes vides */
        if (strcmp(line, ip) == 0) {
            fclose(f);
            pthread_mutex_unlock(&bl_mutex);
            return 1;  /* IP trouvée dans la blacklist */
        }
    }
    
    fclose(f);
    pthread_mutex_unlock(&bl_mutex);
    return 0;  /* IP non bloquée */
}

/*
 * hash_string - Calcule un hash numérique à partir d'une chaîne de caractères
 * @str: chaîne à hasher
 * @return: valeur de hash non signée
 *
 * Utilise l'algorithme djb2 de Daniel J. Bernstein.
 * Formule : hash = hash * 33 + caractère
 * Cet algorithme est rapide et produit une bonne distribution pour les tables de hachage.
 */
unsigned int hash_string(const char *str) {
    unsigned int hash = 5381;  /* Valeur initiale magique de l'algorithme djb2 */
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }
    
    return hash;
}

/*
 * set_socket_timeout - Configure les timeouts de lecture et écriture sur un socket
 * @sock: descripteur du socket
 * @seconds: durée du timeout en secondes
 *
 * Applique SO_RCVTIMEO (timeout de réception) et SO_SNDTIMEO (timeout d'envoi).
 * Si une opération dépasse le timeout, elle échoue avec errno = EWOULDBLOCK.
 */
void set_socket_timeout(int sock, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    /* Timeout pour recv() */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_message(LOG_WARNING, "Cannot set SO_RCVTIMEO: %s", strerror(errno));
    }
    
    /* Timeout pour send() */
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_message(LOG_WARNING, "Cannot set SO_SNDTIMEO: %s", strerror(errno));
    }
}

/*
 * match_pattern - Vérifie si une chaîne correspond à un patron avec wildcards
 * @pattern: patron contenant potentiellement '*' (n'importe quelle séquence) et '?' (un caractère)
 * @str: chaîne à tester
 * @return: 1 si la chaîne correspond au patron, 0 sinon
 *
 * Exemples :
 *   match_pattern("*.html", "page.html")  -> 1
 *   match_pattern("/api/", "/api/users")  -> 1     (wildcard)
 *   match_pattern("file?.txt", "file1.txt") -> 1
 */
int match_pattern(const char *pattern, const char *str) {
    const char *p = pattern;
    const char *s = str;
    
    while (*p && *s) {
        if (*p == '*') {
            /* '*' = correspond à n'importe quelle séquence de caractères */
            while (*p == '*') p++;   /* Sauter les '*' consécutifs */
            if (!*p) return 1;       /* Si le patron finit par '*', c'est un match */
            
            /* Essayer de matcher le reste du patron à chaque position */
            while (*s) {
                if (match_pattern(p, s)) {
                    return 1;  /* Match trouvé récursivement */
                }
                s++;
            }
            return 0;  /* Aucun match trouvé */
        } else if (*p == '?' || *p == *s) {
            /* '?' correspond à un seul caractère, ou les caractères sont identiques */
            p++;
            s++;
        } else {
            return 0;  /* Les caractères ne correspondent pas */
        }
    }
    
    /* Ignorer les '*' restants à la fin du patron */
    while (*p == '*') p++;
    
    /* Match seulement si les deux chaînes sont entièrement parcourues */
    return !*p && !*s;
}

/*
 * get_header_value - Extrait la valeur d'un en-tête HTTP par son nom
 * @headers: chaîne contenant tous les en-têtes HTTP
 * @header_name: nom de l'en-tête à chercher (ex: "Content-Type")
 * @return: valeur de l'en-tête (à libérer avec free()), ou NULL si non trouvé
 *
 * La recherche est insensible à la casse. La valeur retournée
 * est une copie allouée dynamiquement.
 */
char* get_header_value(const char *headers, const char *header_name) {
    if (!headers || !header_name) return NULL;
    
    /* Construire la chaîne de recherche en minuscules */
    char search[256];
    snprintf(search, sizeof(search), "%s:", header_name);
    char *search_lower = strdup(search);
    if (!search_lower) return NULL;
    
    /* Convertir en minuscules pour recherche insensible à la casse */
    for (int i = 0; search_lower[i]; i++) {
        search_lower[i] = tolower(search_lower[i]);
    }
    
    /* Chercher l'en-tête dans les headers */
    const char *pos = headers;
    while ((pos = strstr(pos, search_lower)) != NULL) {
        /* Vérifier que c'est bien le début d'une ligne (pas au milieu d'un mot) */
        const char *line_start = pos;
        while (line_start > headers && *(line_start - 1) != '\n') {
            line_start--;
        }
        
        if (line_start == pos || (line_start == headers && pos == headers)) {
            /* Avancer après le ":" et les espaces */
            pos += strlen(search_lower);
            while (*pos == ' ') pos++;
            
            /* Trouver la fin de la valeur (fin de ligne) */
            const char *end = strstr(pos, "\r\n");
            if (!end) end = strstr(pos, "\n");
            if (!end) end = pos + strlen(pos);
            
            /* Copier et retourner la valeur */
            size_t len = end - pos;
            char *value = malloc(len + 1);
            if (!value) {
                free(search_lower);
                return NULL;
            }
            
            strncpy(value, pos, len);
            value[len] = '\0';
            free(search_lower);
            return value;
        }
        
        pos += strlen(search_lower);
    }
    
    free(search_lower);
    return NULL;  /* En-tête non trouvé */
}

/*
 * url_decode - Décode une chaîne URL-encodée
 * @src: chaîne encodée (ex: "hello%20world" ou "hello+world")
 * @return: chaîne décodée (à libérer avec free()), ou NULL en cas d'erreur
 *
 * Transformations :
 *   %XX -> le caractère avec le code hexadécimal XX (ex: %20 -> espace)
 *   +   -> espace
 */
char* url_decode(const char *src) {
    if (!src) return NULL;
    
    size_t src_len = strlen(src);
    char *decoded = malloc(src_len + 1);  /* La chaîne décodée est au plus aussi longue */
    if (!decoded) return NULL;
    
    char *dst = decoded;
    
    while (*src) {
        if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            /* Séquence %XX : convertir les 2 caractères hex en un octet */
            char hex[3] = {src[1], src[2], '\0'};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            /* '+' = espace dans les formulaires URL-encodés */
            *dst++ = ' ';
            src++;
        } else {
            /* Caractère normal, copier tel quel */
            *dst++ = *src++;
        }
    }
    
    *dst = '\0';
    
    /* Réduire la mémoire à la taille réelle de la chaîne décodée */
    char *result = realloc(decoded, dst - decoded + 1);
    return result ? result : decoded;
}

/*
 * check_rate_limit - Vérifie le débit de requêtes d'une adresse IP
 * @ip: adresse IP du client
 * @return: 1 si la requête est autorisée, 0 si la limite est dépassée
 *
 * Implémente un limiteur de débit simple :
 * - Maximum 100 requêtes par fenêtre de 60 secondes par IP
 * - Les compteurs sont réinitialisés quand la fenêtre expire ou quand l'IP change
 * - Thread-safe grâce à un mutex statique
 *
 * Note: cette implémentation simplifiée ne suit qu'une seule IP à la fois.
 */
// Rate limiter thread-safe
int check_rate_limit(const char *ip) {
    static time_t last_request = 0;           /* Timestamp de la dernière requête */
    static char last_ip[INET_ADDRSTRLEN] = {0}; /* Dernière IP vue */
    static int request_count = 0;              /* Compteur de requêtes dans la fenêtre */
    static time_t window_start = 0;            /* Début de la fenêtre de comptage */
    static pthread_mutex_t rate_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_mutex_lock(&rate_mutex);
    time_t now = time(NULL);
    
    /* Réinitialiser si nouvelle IP ou fenêtre de 60 secondes expirée */
    if (strcmp(ip, last_ip) != 0 || now - window_start > 60) {
        if (strcmp(ip, last_ip) != 0) {
            strncpy(last_ip, ip, sizeof(last_ip) - 1);
            last_ip[sizeof(last_ip) - 1] = '\0';
        }
        request_count = 0;
        window_start = now;
    }
    
    /* Vérifier si la limite de 100 requêtes/minute est dépassée */
    if (request_count >= 100) {
        log_message(LOG_WARNING, "Request limit exceeded for IP: %s (%d requests)", 
                   ip, request_count);
        pthread_mutex_unlock(&rate_mutex);
        return 0;  /* Requête refusée */
    }
    
    /* Protection contre les timestamps négatifs */
    if (now - last_request < 0) {
        last_request = now;
    }
    
    /* Incrémenter le compteur et autoriser la requête */
    request_count++;
    last_request = now;
    
    log_message(LOG_DEBUG, "Rate limit check for %s: %d requests in window", 
               ip, request_count);
    pthread_mutex_unlock(&rate_mutex);
    return 1;  /* Requête autorisée */
}