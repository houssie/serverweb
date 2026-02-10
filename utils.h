#ifndef UTILS_H
#define UTILS_H

#include "config.h"
#include <netdb.h>  // Ajouté pour struct hostent

int create_server_socket(int port);
int connect_to_backend(const char *host, int port);
void send_http_response(int sock, int status_code, const char *message, const char *content_type, const char *body);
int read_http_request(int sock, char *buffer, int size);
int forward_data(int from_sock, int to_sock, char *buffer, int size);
int is_blacklisted(const char *ip);
int check_rate_limit(const char *ip);
char* url_decode(const char *src);
char* get_header_value(const char *headers, const char *header_name);
void set_socket_timeout(int sock, int seconds);
unsigned int hash_string(const char *str);
int match_pattern(const char *pattern, const char *str);

#endif