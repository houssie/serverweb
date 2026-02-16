/*
 * test_client.c - Client de test simple pour le proxy inverse
 *
 * Ce programme se connecte au proxy sur le port 8085
 * et envoie une requête HTTP GET pour vérifier que le proxy
 * fonctionne correctement. La réponse reçue est affichée
 * dans le terminal.
 *
 * Utilisation : ./test_client
 */

/* === Includes nécessaires === */
#include <stdio.h>        /* printf, perror */
#include <stdlib.h>       /* Fonctions standard */
#include <string.h>       /* strlen, memset */
#include <unistd.h>       /* close() */
#include <sys/socket.h>   /* socket(), connect(), send(), recv() */
#include <netinet/in.h>   /* struct sockaddr_in, htons() */
#include <arpa/inet.h>    /* inet_pton() */

int main() {
    /* === Création du socket TCP === */
    /* AF_INET = IPv4, SOCK_STREAM = TCP, 0 = protocole par défaut */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");  /* Afficher l'erreur système */
        return 1;
    }

    /* === Configuration de l'adresse du proxy === */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));          /* Initialiser à zéro */
    addr.sin_family = AF_INET;               /* IPv4 */
    addr.sin_port = htons(8085);             /* Port du proxy (conversion en ordre réseau) */
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);  /* Adresse localhost */

    /* === Connexion au proxy === */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");  /* Afficher l'erreur si la connexion échoue */
        close(sock);
        return 1;
    }

    /* === Envoi d'une requête HTTP GET === */
    /* Requête minimale HTTP/1.1 vers la racine "/" */
    const char *request = "GET / HTTP/1.1\r\nHost: localhost:8085\r\n\r\n";
    send(sock, request, strlen(request), 0);

    /* === Lecture et affichage de la réponse === */
    /* On lit la réponse du proxy par morceaux de 1024 octets */
    char buffer[1024];
    int n;
    while ((n = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[n] = '\0';   /* Terminer la chaîne pour printf */
        printf("%s", buffer);
        fflush(stdout);     /* Forcer l'affichage immédiat (pas de buffering) */
    }

    /* === Fermeture du socket === */
    close(sock);
    return 0;  /* Fin du programme */
}