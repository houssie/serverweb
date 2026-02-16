/*
 * utils.h - Interface des fonctions utilitaires
 * Fournit les fonctions réseau, de sécurité et de manipulation
 * de données utilisées par l'ensemble du projet.
 */

#ifndef UTILS_H
#define UTILS_H

#include "config.h"
#include <netdb.h>  /* Pour struct hostent (résolution DNS) */

/* Crée un socket serveur TCP qui écoute sur le port donné */
int create_server_socket(int port);

/* Se connecte à un serveur backend et retourne le socket (ou -1 en cas d'erreur) */
int connect_to_backend(const char *host, int port);

/* Envoie une réponse HTTP complète au client (code + headers + body) */
void send_http_response(int sock, int status_code, const char *message, const char *content_type, const char *body);

/* Lit une requête HTTP depuis un socket client, retourne le nombre d'octets lus */
int read_http_request(int sock, char *buffer, int size);

/* Transfère des données d'un socket source vers un socket destination */
int forward_data(int from_sock, int to_sock, char *buffer, int size);

/* Vérifie si une adresse IP est dans la liste noire (retourne 1 si bloquée) */
int is_blacklisted(const char *ip);

/* Vérifie le débit de requêtes d'une IP (retourne 0 si limite dépassée) */
int check_rate_limit(const char *ip);

/* Décode une chaîne URL-encodée (%20 -> espace, + -> espace, etc.) */
char* url_decode(const char *src);

/* Extrait la valeur d'un en-tête HTTP par son nom */
char* get_header_value(const char *headers, const char *header_name);

/* Configure le timeout de lecture/écriture sur un socket */
void set_socket_timeout(int sock, int seconds);

/* Calcule un hash (algorithme djb2) d'une chaîne de caractères */
unsigned int hash_string(const char *str);

/* Vérifie si une chaîne correspond à un patron avec wildcards (* et ?) */
int match_pattern(const char *pattern, const char *str);

#endif