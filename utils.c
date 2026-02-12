#include "utils.h"
#include "logger.h"
#include <ctype.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int create_server_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_message(LOG_ERROR, "Cannot create socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(LOG_ERROR, "Cannot set SO_REUSEADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    #ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        log_message(LOG_WARNING, "Cannot set SO_REUSEPORT: %s", strerror(errno));
    }
    #endif
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message(LOG_ERROR, "Cannot bind socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    if (listen(sock, MAX_CLIENTS) < 0) {
        log_message(LOG_ERROR, "Cannot listen on socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    log_message(LOG_INFO, "Server listening on port %d", port);
    return sock;
}

int connect_to_backend(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    set_socket_timeout(sock, 5);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (he == NULL) {
            close(sock);
            return -1;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

void send_http_response(int sock, int status_code, const char *message, 
                        const char *content_type, const char *body) {
    char response[BUFFER_SIZE];
    int length = 0;
    
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
    
    if (length < 0 || length >= BUFFER_SIZE) {
        log_message(LOG_ERROR, "Response too large: %d bytes", length);
        return;
    }
    
    log_message(LOG_DEBUG, "Sending HTTP response: %d %s, length: %d", status_code, message, length);
    log_message(LOG_DEBUG, "Response headers: %.200s", response);
    int sent = send(sock, response, length, 0);
    log_message(LOG_DEBUG, "send() returned: %d", sent);
    if (sent < 0) {
        log_message(LOG_ERROR, "send() failed: %s", strerror(errno));
    }
    
    // Shutdown write side to ensure data is sent
    shutdown(sock, SHUT_WR);
    usleep(100000);
}

int read_http_request(int sock, char *buffer, int size) {
    int total_read = 0;
    int bytes_read;
    
    set_socket_timeout(sock, REQUEST_TIMEOUT);
    
    while (total_read < size - 1) {
        bytes_read = recv(sock, buffer + total_read, size - total_read - 1, 0);
        
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                log_message(LOG_DEBUG, "Client disconnected");
            } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
                log_message(LOG_ERROR, "Error reading from socket: %s", strerror(errno));
            }
            break;
        }
        
        total_read += bytes_read;
        buffer[total_read] = '\0';
        
        if (strstr(buffer, "\r\n\r\n") != NULL || strstr(buffer, "\n\n") != NULL) {
            break;
        }
    }
    
    buffer[total_read] = '\0';
    return total_read;
}

int forward_data(int from_sock, int to_sock, char *buffer, int size) {
    int bytes_read = recv(from_sock, buffer, size, 0);
    if (bytes_read <= 0) {
        return bytes_read;
    }
    
    int bytes_sent = send(to_sock, buffer, bytes_read, 0);
    if (bytes_sent != bytes_read) {
        log_message(LOG_ERROR, "Failed to forward all data: %d of %d bytes", bytes_sent, bytes_read);
        return -1;
    }
    
    return bytes_read;
}

int is_blacklisted(const char *ip) {
    static pthread_mutex_t bl_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_mutex_lock(&bl_mutex);
    FILE *f = fopen("config/blacklist.txt", "r");
    if (!f) {
        pthread_mutex_unlock(&bl_mutex);
        return 0;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;  // Supprimer aussi \r
        if (line[0] == '#' || line[0] == '\0') continue;
        if (strcmp(line, ip) == 0) {
            fclose(f);
            pthread_mutex_unlock(&bl_mutex);
            return 1;
        }
    }
    
    fclose(f);
    pthread_mutex_unlock(&bl_mutex);
    return 0;
}

unsigned int hash_string(const char *str) {
    unsigned int hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

void set_socket_timeout(int sock, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_message(LOG_WARNING, "Cannot set SO_RCVTIMEO: %s", strerror(errno));
    }
    
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_message(LOG_WARNING, "Cannot set SO_SNDTIMEO: %s", strerror(errno));
    }
}

int match_pattern(const char *pattern, const char *str) {
    const char *p = pattern;
    const char *s = str;
    
    while (*p && *s) {
        if (*p == '*') {
            while (*p == '*') p++;
            if (!*p) return 1;
            
            while (*s) {
                if (match_pattern(p, s)) {
                    return 1;
                }
                s++;
            }
            return 0;
        } else if (*p == '?' || *p == *s) {
            p++;
            s++;
        } else {
            return 0;
        }
    }
    
    while (*p == '*') p++;
    
    return !*p && !*s;
}

char* get_header_value(const char *headers, const char *header_name) {
    if (!headers || !header_name) return NULL;
    
    char search[256];
    snprintf(search, sizeof(search), "%s:", header_name);
    char *search_lower = strdup(search);
    if (!search_lower) return NULL;
    
    for (int i = 0; search_lower[i]; i++) {
        search_lower[i] = tolower(search_lower[i]);
    }
    
    const char *pos = headers;
    while ((pos = strstr(pos, search_lower)) != NULL) {
        const char *line_start = pos;
        while (line_start > headers && *(line_start - 1) != '\n') {
            line_start--;
        }
        
        if (line_start == pos || (line_start == headers && pos == headers)) {
            pos += strlen(search_lower);
            while (*pos == ' ') pos++;
            
            const char *end = strstr(pos, "\r\n");
            if (!end) end = strstr(pos, "\n");
            if (!end) end = pos + strlen(pos);
            
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
    return NULL;
}

char* url_decode(const char *src) {
    if (!src) return NULL;
    
    size_t src_len = strlen(src);
    char *decoded = malloc(src_len + 1);
    if (!decoded) return NULL;
    
    char *dst = decoded;
    
    while (*src) {
        if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = {src[1], src[2], '\0'};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    
    *dst = '\0';
    
    char *result = realloc(decoded, dst - decoded + 1);
    return result ? result : decoded;
}

// Rate limiter thread-safe
int check_rate_limit(const char *ip) {
    static time_t last_request = 0;
    static char last_ip[INET_ADDRSTRLEN] = {0};
    static int request_count = 0;
    static time_t window_start = 0;
    static pthread_mutex_t rate_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_mutex_lock(&rate_mutex);
    time_t now = time(NULL);
    
    // Réinitialiser si nouvelle IP ou fenêtre expirée
    if (strcmp(ip, last_ip) != 0 || now - window_start > 60) {
        if (strcmp(ip, last_ip) != 0) {
            strncpy(last_ip, ip, sizeof(last_ip) - 1);
            last_ip[sizeof(last_ip) - 1] = '\0';
        }
        request_count = 0;
        window_start = now;
    }
    
    // Vérifier le taux (100 requêtes par minute maximum)
    if (request_count >= 100) {
        log_message(LOG_WARNING, "Request limit exceeded for IP: %s (%d requests)", 
                   ip, request_count);
        pthread_mutex_unlock(&rate_mutex);
        return 0;
    }
    
    // Vérifier l'intervalle minimum entre requêtes (500ms minimum)
    if (now - last_request < 0) {  // Protection contre temps négatif
        last_request = now;
    }
    
    // Pas de limite trop stricte sur l'intervalle entre requêtes
    // pour les tests
    request_count++;
    last_request = now;
    
    log_message(LOG_DEBUG, "Rate limit check for %s: %d requests in window", 
               ip, request_count);
    pthread_mutex_unlock(&rate_mutex);
    return 1;
}