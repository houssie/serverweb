/*
 * backend_manager.h - Interface de gestion des serveurs backend
 * Fournit les fonctions pour charger, surveiller et gérer
 * les serveurs backend du reverse proxy.
 */

#ifndef BACKEND_MANAGER_H
#define BACKEND_MANAGER_H

#include "config.h"

/* Charge la liste des backends depuis un fichier de configuration */
Backend* load_backends(const char *filename, int *count);

/* Libère la mémoire et les mutex de tous les backends */
void free_backends(Backend *backends, int count);

/* Incrémente le compteur de connexions actives d'un backend (thread-safe) */
void increment_backend_connections(Backend *backend);

/* Décrémente le compteur de connexions actives d'un backend (thread-safe) */
void decrement_backend_connections(Backend *backend);

/* Met à jour l'état de santé d'un backend après une tentative de connexion */
void update_backend_health(Backend *backend, int is_healthy);

/* Fonction du thread de vérification périodique de la santé des backends */
void* health_check_thread(void *arg);

/* Calcule le poids total de tous les backends en bonne santé */
int get_total_backends_weight(Backend *backends, int count);

/* Affiche les statistiques de tous les backends dans le journal */
void print_backend_stats(Backend *backends, int count);

#endif