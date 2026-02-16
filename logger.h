/*
 * logger.h - Interface du système de journalisation
 * Fournit les fonctions pour écrire des messages de log
 * avec horodatage et niveaux de sévérité.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include "config.h"

/* Initialise le logger avec un fichier de sortie (NULL = stdout) */
void init_logger(const char *log_file);

/* Écrit un message formaté dans le journal avec le niveau de sévérité donné */
void log_message(LogLevel level, const char *format, ...);

/* Ferme le fichier de log et libère les ressources */
void close_logger();

#endif