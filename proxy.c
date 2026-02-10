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

static volatile int running = 1;
static volatile int shutdown_requested = 0;
static Cache *global_cache = NULL;
static CacheRules *global_cache_rules = NULL;
static Backend *backends = NULL;
static int backend_count = 0;
static LBStrategy lb_strategy = LB_ROUND_ROBIN;
static int active_threads = 0;
static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int sig) {
    if (!shutdown_requested) {
        log_message(LOG_INFO, "Received signal %d, requesting shutdown...", sig);
        shutdown_requested = 1;
        running = 0;
    }
}

int parse_http_request(const char *raw, HttpRequest *req) {
    memset(req, 0, sizeof(HttpRequest));
    
    int parsed = sscanf(raw, "%15s %1023s %15s", req->method, req->path, req->protocol);
    if (parsed != 3) {
        log_message(LOG_ERROR, "Failed to parse HTTP request line, parsed %d fields", parsed);
        log_message(LOG_DEBUG, "Raw request line: %.100s", raw);
        return 0;
    }
    
    log_message(LOG_DEBUG, "Parsed request: method='%s', path='%s', protocol='%s'", 
                req->method, req->path, req->protocol);
    
    const char *headers_start = strstr(raw, "\r\n");
    if (!headers_start) {
        headers_start = strstr(raw, "\n");
        if (!headers_start) {
            log_message(LOG_ERROR, "No headers found in request");
            return 0;
        }
    }
    
    const char *headers_end = strstr(headers_start + (headers_start[1] == '\n' ? 1 : 2), "\r\n\r\n");
    if (!headers_end) {
        headers_end = strstr(headers_start + (headers_start[1] == '\n' ? 1 : 2), "\n\n");
        if (!headers_end) {
            log_message(LOG_ERROR, "Incomplete headers in request");
            return 0;
        }
    }
    
    size_t headers_len = headers_end - headers_start - 2;
    if (headers_len >= sizeof(req->headers) - 1) {
        log_message(LOG_ERROR, "Headers too long: %zu bytes", headers_len);
        return 0;
    }
    
    strncpy(req->headers, headers_start + 2, headers_len);
    req->headers[headers_len] = '\0';
    
    log_message(LOG_DEBUG, "Parsed headers (%zu bytes): %.200s", headers_len, req->headers);
    
    char *host_line = strstr(req->headers, "Host:");
    if (host_line) {
        char host_buffer[256];
        if (sscanf(host_line, "Host: %255[^\r\n]", host_buffer) == 1) {
            char *colon = strchr(host_buffer, ':');
            if (colon) {
                *colon = '\0';
                strncpy(req->host, host_buffer, sizeof(req->host) - 1);
                req->host[sizeof(req->host) - 1] = '\0';
                req->port = atoi(colon + 1);
            } else {
                strncpy(req->host, host_buffer, sizeof(req->host) - 1);
                req->host[sizeof(req->host) - 1] = '\0';
                req->port = 80;
            }
        }
    }
    
    return 1;
}

void serve_static(int client_sock, const char *path) {
    char full_path[2048];  // Augmenté pour éviter le warning
    int path_len = snprintf(full_path, sizeof(full_path), "web%s", path);
    
    if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
        log_message(LOG_ERROR, "Path too long: %s", path);
        send_http_response(client_sock, 414, "URI Too Long", "text/plain", "Path too long");
        return;
    }
    
    FILE *file = fopen(full_path, "rb");
    if (!file) {
        log_message(LOG_ERROR, "Cannot open file: %s", full_path);
        send_http_response(client_sock, 404, "Not Found", "text/plain", "File not found");
        return;
    }
    
    struct stat st;
    if (stat(full_path, &st) != 0) {
        log_message(LOG_ERROR, "Cannot stat file: %s", full_path);
        fclose(file);
        send_http_response(client_sock, 404, "Not Found", "text/plain", "File not found");
        return;
    }
    
    long file_size = st.st_size;
    log_message(LOG_DEBUG, "File size: %ld", file_size);
    
    const char *content_type = "text/plain";
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
    
    char headers[2048];  // Augmenté
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
    
    log_message(LOG_DEBUG, "Sending headers: %.100s", headers);
    ssize_t sent = send(client_sock, headers, (size_t)header_len, 0);
    if (sent != header_len) {
        log_message(LOG_ERROR, "Failed to send headers");
        fclose(file);
        return;
    }
    
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

void serve_php(int client_sock, const char *path, const char *client_ip) {
    (void)client_ip;  // Marquer comme utilisé pour éviter le warning
    log_message(LOG_DEBUG, "Starting serve_php for path: %s", path);
    char full_path[2048];  // Augmenté
    int path_len = snprintf(full_path, sizeof(full_path), "web%s", path);
    
    if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
        log_message(LOG_ERROR, "PHP path too long: %s", path);
        send_http_response(client_sock, 414, "URI Too Long", "text/plain", "Path too long");
        return;
    }
    
    log_message(LOG_DEBUG, "Full path: %s", full_path);
    
    struct stat st;
    if (stat(full_path, &st) != 0) {
        log_message(LOG_ERROR, "PHP file not found: %s", full_path);
        send_http_response(client_sock, 404, "Not Found", "text/plain", "PHP file not found");
        return;
    }
    
    char command[4096];  // Augmenté
    int cmd_len = snprintf(command, sizeof(command), "php -f %s", full_path);
    
    if (cmd_len < 0 || (size_t)cmd_len >= sizeof(command)) {
        log_message(LOG_ERROR, "PHP command too long");
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "Command too long");
        return;
    }
    
    log_message(LOG_DEBUG, "PHP command: %s", command);
    
    FILE *fp = popen(command, "r");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to popen PHP command");
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "PHP execution failed");
        return;
    }
    log_message(LOG_DEBUG, "popen successful");
    
    char buffer[BUFFER_SIZE];
    size_t total_size = 0;
    size_t capacity = BUFFER_SIZE * 4;
    char *output = malloc(capacity);
    if (!output) {
        log_message(LOG_ERROR, "Failed to malloc output buffer");
        pclose(fp);
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "Memory error");
        return;
    }
    output[0] = '\0';
    log_message(LOG_DEBUG, "Output buffer allocated");
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t len = strlen(buffer);
        if (total_size + len + 1 > capacity) {
            capacity *= 2;
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
    
    int status = pclose(fp);
    log_message(LOG_DEBUG, "pclose status: %d", status);
    if (status != 0) {
        log_message(LOG_ERROR, "PHP script exited with status: %d", status);
        free(output);
        send_http_response(client_sock, 500, "Internal Server Error", "text/plain", "PHP script error");
        return;
    }
    
    log_message(LOG_DEBUG, "Sending PHP response");
    
    char response[BUFFER_SIZE * 2];  // Augmenté
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

void* handle_client(void *arg) {
    ClientArgs *args = (ClientArgs *)arg;
    int client_sock = args->client_socket;
    char client_ip[INET_ADDRSTRLEN];
    strcpy(client_ip, args->client_ip);
    
    log_message(LOG_DEBUG, "Starting handle_client for %s", client_ip);
    
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
    
    char full_path[2048];  // Augmenté
    if (strcmp(req.path, "/") == 0) {
        strcpy(full_path, "web/index.html");
    } else {
        int path_len = snprintf(full_path, sizeof(full_path), "web%s", req.path);
        if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
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
    
    struct stat st;
    if (stat(full_path, &st) == 0) {
        log_message(LOG_DEBUG, "File exists, serving %s", full_path);
        if (strstr(req.path, ".php") != NULL) {
            serve_php(client_sock, req.path, client_ip);
        } else {
            const char *serve_path = (strcmp(req.path, "/") == 0) ? "/index.html" : req.path;
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
    
    log_message(LOG_DEBUG, "File not found locally, trying backend for: %s", req.path);
    
    int cache_max_age = 0;
    size_t cache_max_size = 0;
    int should_cache = should_cache_request(request_buffer) && 
                      cache_rules_match(global_cache_rules, req.path, &cache_max_age, &cache_max_size);
    
    log_message(LOG_DEBUG, "Cache check for %s: should_cache=%d, max_age=%d, max_size=%zu", 
                req.path, should_cache, cache_max_age, cache_max_size);
    
    if (should_cache && cache_max_age > 0) {
        char cache_key[CACHE_KEY_SIZE];
        snprintf(cache_key, sizeof(cache_key), "%s %s %s", req.method, req.path, req.headers);
        
        char *cached_response = cache_get(global_cache, cache_key);
        if (cached_response) {
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
    
    Backend *backend = select_backend(args->backends, args->backend_count, 
                                     lb_strategy, client_ip);
    
    if (!backend) {
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
    
    int backend_sock = connect_to_backend(backend->host, backend->port);
    if (backend_sock < 0) {
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
    
    if (send(backend_sock, request_buffer, (size_t)request_len, 0) != request_len) {
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
    
    char response_buffer[BUFFER_SIZE];
    int total_response_size = 0;
    char *full_response = NULL;
    int can_cache_response = should_cache_request(request_buffer) && should_cache;
    
    while (1) {
        int bytes = recv(backend_sock, response_buffer, sizeof(response_buffer) - 1, 0);
        
        if (bytes <= 0) {
            break;
        }
        
        int sent = send(client_sock, response_buffer, (size_t)bytes, 0);
        if (sent != bytes) {
            log_message(LOG_WARNING, "Failed to send all data to client: %d of %d bytes", 
                       sent, bytes);
            break;
        }
        
        if (can_cache_response && (size_t)total_response_size + (size_t)bytes <= cache_max_size) {
            char *new_full_response = realloc(full_response, (size_t)total_response_size + (size_t)bytes + 1);
            if (!new_full_response) {
                log_message(LOG_ERROR, "Failed to realloc for caching");
                free(full_response);
                full_response = NULL;
                can_cache_response = 0;
            } else {
                full_response = new_full_response;
                memcpy(full_response + total_response_size, response_buffer, (size_t)bytes);
                total_response_size += bytes;
            }
        }
    }
    
    if (can_cache_response && full_response && total_response_size > 0 && 
        (size_t)total_response_size <= cache_max_size) {
        full_response[total_response_size] = '\0';
        
        if (should_cache_response(full_response)) {
            char cache_key[CACHE_KEY_SIZE];
            snprintf(cache_key, sizeof(cache_key), "%s %s %s", req.method, req.path, req.headers);
            
            time_t expiry = time(NULL) + cache_max_age;
            time_t header_expiry = get_cache_expiry_from_headers(full_response);
            if (header_expiry > 0 && header_expiry < expiry) {
                expiry = header_expiry;
            }
            
            cache_put(global_cache, cache_key, full_response, (size_t)total_response_size, expiry);
            
            log_message(LOG_INFO, "Cached response for: %s (size: %d, expires in %ld seconds)", 
                       req.path, total_response_size, expiry - time(NULL));
        }
    }
    
    if (full_response) {
        free(full_response);
    }
    
    update_backend_health(backend, 1);
    decrement_backend_connections(backend);
    close(backend_sock);
    close(client_sock);
    
    log_message(LOG_INFO, "Connection closed for %s", client_ip);
    free(args);
    
    pthread_mutex_lock(&threads_mutex);
    active_threads--;
    pthread_mutex_unlock(&threads_mutex);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    int proxy_port = 9999;
    char *config_file = "config/backends.cfg";
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            proxy_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_file = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            lb_strategy = atoi(argv[++i]);
        }
    }
    
    init_logger("proxy.log");
    log_message(LOG_INFO, "Starting reverse proxy on port %d", proxy_port);
    
    // Set up signal handlers
    // signal(SIGINT, signal_handler);
    // signal(SIGTERM, signal_handler);
    
    backends = load_backends(config_file, &backend_count);
    if (!backends || backend_count == 0) {
        log_message(LOG_ERROR, "No backends loaded from %s", config_file);
        
        // Créer un backend par défaut pour les tests
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
    
    if (!backends) {
        log_message(LOG_ERROR, "Failed to initialize backends");
        close_logger();
        return 1;
    }
    
    global_cache = cache_init(CACHE_CAPACITY);
    
    global_cache_rules = cache_rules_init();
    if (!cache_rules_load(global_cache_rules, "config/cache_rules.cfg")) {
        log_message(LOG_WARNING, "Failed to load cache rules, using default behavior");
    }
    
    pthread_t health_thread;
    typedef struct {
        Backend *backends;
        int count;
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
            pthread_detach(health_thread);
        }
    }
    
    int server_sock = create_server_socket(proxy_port);
    if (server_sock < 0) {
        log_message(LOG_ERROR, "Failed to create server socket");
        close_logger();
        return 1;
    }
    
    log_message(LOG_INFO, "Proxy server ready. Press Ctrl+C to stop.");
    
    while (running) {
        log_message(LOG_DEBUG, "Waiting for connection, running=%d, active_threads=%d", 
                   running, active_threads);
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (running) {
                log_message(LOG_ERROR, "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        pthread_mutex_lock(&threads_mutex);
        if (active_threads >= MAX_CLIENTS) {
            log_message(LOG_WARNING, "Too many active threads, rejecting connection");
            close(client_sock);
            pthread_mutex_unlock(&threads_mutex);
            continue;
        }
        active_threads++;
        pthread_mutex_unlock(&threads_mutex);
        
        ClientArgs *args = malloc(sizeof(ClientArgs));
        if (!args) {
            log_message(LOG_ERROR, "Failed to allocate client args");
            close(client_sock);
            
            pthread_mutex_lock(&threads_mutex);
            active_threads--;
            pthread_mutex_unlock(&threads_mutex);
            
            continue;
        }
        
        args->client_socket = client_sock;
        args->client_addr = client_addr;
        args->backends = backends;
        args->backend_count = backend_count;
        args->cache = global_cache;
        inet_ntop(AF_INET, &client_addr.sin_addr, args->client_ip, INET_ADDRSTRLEN);
        
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client, args) != 0) {
            log_message(LOG_ERROR, "Failed to create client thread");
            close(client_sock);
            free(args);
            
            pthread_mutex_lock(&threads_mutex);
            active_threads--;
            pthread_mutex_unlock(&threads_mutex);
        } else {
            pthread_detach(client_thread);
        }
    }
    
    log_message(LOG_INFO, "Shutting down...");
    
    close(server_sock);
    
    if (backends) {
        print_backend_stats(backends, backend_count);
        free_backends(backends, backend_count);
    }
    
    if (global_cache) {
        cache_print_stats(global_cache);
        cache_free(global_cache);
    }
    
    if (global_cache_rules) {
        cache_rules_free(global_cache_rules);
    }
    
    close_logger();
    
    log_message(LOG_INFO, "Proxy server stopped");
    
    return 0;
}