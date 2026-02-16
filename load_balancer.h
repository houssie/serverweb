/*
 * load_balancer.h - Interface du répartiteur de charge
 * Fournit les fonctions pour sélectionner le meilleur backend
 * selon différentes stratégies de load balancing.
 */

#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "config.h"

/* Sélectionne un backend selon la stratégie choisie et l'IP du client */
Backend* select_backend(Backend *backends, int count, LBStrategy strategy, const char *client_ip);

/* Affiche les statistiques de répartition de charge (% par backend) */
void print_load_balancing_stats(Backend *backends, int count);

/* Remet à zéro les compteurs de connexions de tous les backends */
void reset_backend_stats(Backend *backends, int count);

#endif