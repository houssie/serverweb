/*
 * logger.c - Implémentation du système de journalisation
 * Gère l'écriture thread-safe de messages horodatés dans un fichier de log.
 * Chaque message inclut la date/heure en millisecondes et le niveau de sévérité.
 */

#include "logger.h"
#include <stdarg.h>      /* Pour les fonctions à arguments variables (va_list, va_start, etc.) */
#include <sys/time.h>    /* Pour gettimeofday() : obtenir le temps avec précision microseconde */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

/* Variables statiques du module */
static FILE *log_file = NULL;                                   /* Fichier de sortie du log */
static LogLevel current_level = LOG_DEBUG;                      /* Niveau minimum de log affiché */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;   /* Mutex pour protéger l'écriture (thread-safe) */

/*
 * init_logger - Initialise le système de journalisation
 * @filename: chemin du fichier de log (NULL pour écrire sur stdout)
 * Ouvre le fichier en mode "append" (ajout en fin de fichier).
 * Si l'ouverture échoue, redirige vers stdout.
 */
void init_logger(const char *filename) {
    if (filename) {
        log_file = fopen(filename, "a");   /* Ouvrir en mode ajout */
        if (!log_file) {
            fprintf(stderr, "Cannot open log file: %s\n", filename);
            log_file = stdout;             /* Fallback vers la sortie standard */
        }
    } else {
        log_file = stdout;
    }
}

/*
 * log_message - Écrit un message dans le journal
 * @level: niveau de sévérité du message (DEBUG, INFO, WARNING, ERROR)
 * @format: chaîne de format (comme printf)
 * @...: arguments variables pour le format
 * 
 * Le message est ignoré si le niveau est inférieur au niveau courant.
 * Format de sortie : [YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] message
 */
void log_message(LogLevel level, const char *format, ...) {
    if (level < current_level) return;  /* Filtrer selon le niveau minimum configuré */
    
    /* Obtenir le temps actuel avec précision milliseconde */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    
    /* Formater l'horodatage en chaîne lisible */
    char time_buffer[26];
    strftime(time_buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Convertir le niveau en texte */
    const char *level_str;
    switch(level) {
        case LOG_DEBUG: level_str = "DEBUG"; break;
        case LOG_INFO: level_str = "INFO"; break;
        case LOG_WARNING: level_str = "WARN"; break;
        case LOG_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }
    
    /* Écriture thread-safe protégée par mutex */
    pthread_mutex_lock(&log_mutex);
    
    /* Écrire l'en-tête : [date.millisecondes] [NIVEAU] */
    fprintf(log_file, "[%s.%.3d] [%s] ", time_buffer, (int)(tv.tv_usec / 1000), level_str);
    
    /* Écrire le message formaté avec les arguments variables */
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");   /* Ajouter un retour à la ligne */
    fflush(log_file);          /* Forcer l'écriture immédiate sur disque */
    pthread_mutex_unlock(&log_mutex);
}

/*
 * close_logger - Ferme le système de journalisation
 * Ferme le fichier de log (sauf s'il s'agit de stdout).
 */
void close_logger() {
    if (log_file && log_file != stdout) {
        fclose(log_file);
    }
}