#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include<stdarg.h>
#include <arpa/inet.h>

#include <unistd.h>

#define ERROR  "\x1B[31m"
#define SUCCESS  "\x1B[32m"
#define WARNING  "\x1B[33m"
#define DEBUG  "\x1B[34m"
#define NORMAL  "\x1B[0m"
#define INFO "\x1B[35m"
#define IMAP_PORT 143
#define IMAP_TLS_PORT 993

void debugPrint(const char *format, ...) {
#ifndef NDEBUG
    va_list args;
    va_start(args, format);
    printf("%s[DEBUG]", DEBUG);
    vprintf(format, args);
    va_end(args);
    printf("%s\n", NORMAL);
#endif
}
void warningPrint(const char *format, ...)
{
#ifndef NDEBUG
    va_list args;
    va_start(args, format);
    printf("%s[WARNING]", WARNING);
    vprintf(format, args);
    va_end(args);
    printf("%s\n", NORMAL);
#endif
}
void errorPrint(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%s[ERROR]", ERROR);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s\n", NORMAL);
}
void infoPrint(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("%s[INFO]", INFO);
    vprintf(format, args);
    va_end(args);
    printf("%s\n", NORMAL);
}
void print_usage() {
    fprintf(stderr, "Usage: fetchmail -u <username> -p <password> [-f <folder>] [-n <messageNum>] [-t] <command> <server_name>\n");
}
char* ipStringFromAddr(const struct sockaddr *addr, char* dst, const int size) {
    switch (addr->sa_family) {
        case AF_INET:
            if (inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, dst, size) != NULL) {
                return dst;
            }
            break;
        case AF_INET6:
            if (inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, dst, size) != NULL) {
                return dst;
            }
            break;
        default:
            break;
    }
    return NULL;
}
struct addrinfo* reverseList(struct addrinfo* head) {
    struct addrinfo *prev = NULL;
    struct addrinfo *current = head;
    struct addrinfo *next = NULL;
    while (current != NULL) {
        next = current->ai_next;
        current->ai_next = prev;
        prev = current;
        current = next;
    }
    head = prev;
    return head;
}
int main(const int argc, char **argv)
{
    char *username = NULL;
    char *password = NULL;
    char *folder = NULL;
    char *messageNum = NULL;
    char *command = NULL;
    int tflag = 0;
    int opt;
    int command_index;
    int server_index;
    //default server name
#ifdef NDEBUG
    char *server_name = NULL;
#else
    //char *server_name = "unimelb-comp30023-2024.cloud.edu.au";
    char *server_name = "127.0.0.1";
#endif
    //parse the command line arguments
#ifdef NDEBUG
    while ((opt = getopt(argc, argv, "u:p:f:n:t")) != -1) {
        switch (opt) {
        case 'u':
            username = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 'f':
            folder = optarg;
            break;
        case 'n':
            messageNum = optarg;
            break;
        case 't':
            tflag = 1;
            break;
        default:
            errorPrint("Invalid argument provided");
            print_usage();
            return 1;
        }
    }
    command_index = optind;
    server_index = optind + 1;
    if (!(username && password)) {
        errorPrint("Username and password are required");
        print_usage();
        exit(EXIT_FAILURE);
    }
    infoPrint("Username: %s", username);
    infoPrint("Password: %s", password);
    if (folder) {
        infoPrint("Folder: %s", folder);
    }
    if (messageNum) {
        infoPrint("Message Number: %s", messageNum);
    }
    if(tflag) {
        infoPrint("TLS Enabled");
    }
    if (command_index >= argc) {
        errorPrint("No command provided");
        print_usage();
        exit(EXIT_FAILURE);
    }
    if (server_index >= argc) {
        errorPrint("No server name provided");
        print_usage();
        exit(EXIT_FAILURE);
    }
    command = argv[command_index];
    server_name = argv[server_index];
    infoPrint("Command: %s", command);
    infoPrint("Server Name: %s", server_name);
#endif
    struct addrinfo *result = 0;
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
#ifndef NDEBUG
    debugPrint("Attempting to resolve IPs for %s", server_name);
    if (getaddrinfo(server_name, NULL, &hints, &result))
    {
        errorPrint("getaddrinfo failed to resolve: %s", strerror(errno));
        return 1;
    }
#else
    if (getaddrinfo(argv[1], NULL, &hints, &result)){
        errorPrint("getaddrinfo failed to resolve: %s", strerror(errno));
        return 1;
    }
#endif
    if(result == NULL){
        errorPrint("Failed to get address info");
        return 1;
    }
    //print the resolved IP protocol if IPV4 or IPV6 or based on the family
    const struct addrinfo *reversed = reverseList(result);
#ifndef NDEBUG
    //print resolved IP addresses
    for(const struct addrinfo *addr = reversed; addr != NULL; addr = addr->ai_next)
    {
        char dst[1024];
        switch(addr->ai_family)
        {
        case AF_INET:
            if (inet_ntop(AF_INET, &((struct sockaddr_in *)addr->ai_addr)->sin_addr, dst, sizeof(dst)) != NULL){
                infoPrint("Resolved IPv4 address: %s", dst);
            } else {
                errorPrint("inet_ntop failed to convert: %s", strerror(errno));
            }
            break;
        case AF_INET6:
            if (inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr, dst, sizeof(dst)) != NULL) {
                infoPrint("Resolved IPv6 address: %s", dst);
            } else {
                errorPrint("inet_ntop failed to convert: %s", strerror(errno));
            }
            break;
        default:
            errorPrint("Unknown ai_family: %d", addr->ai_family);
            return 1;
            break;
        }
    }
#endif
    if(reversed->ai_family != AF_INET && reversed->ai_family != AF_INET6)
    {
        errorPrint("Unknown ai_family: %d", reversed->ai_family);
        return 1;
    }
    int sock = -1;
    int connected = -1;
    int fallback = 0;
    for(const struct addrinfo *addr = reversed; addr != NULL; addr = addr->ai_next)
    {
        debugPrint("Attemping to creating Socket");
        sock = socket(reversed->ai_family, reversed->ai_socktype, reversed->ai_protocol);
        if (sock < 0) {
            warningPrint("Socket creation failed: %s", strerror(errno));
            continue;
        }
        debugPrint("Socket created successfully");
        debugPrint("Setting IMAP port of sockaddr: %d", tflag ? IMAP_TLS_PORT : IMAP_PORT);
        switch (addr->ai_family)
        {
            case AF_INET:
                if(fallback == 0)
                {
                    warningPrint("Failed to connect via IPV6 falling back to IPV4");
                    fallback = 1;
                }
                ((struct sockaddr_in *)reversed->ai_addr)->sin_port = htons(tflag ? IMAP_TLS_PORT : IMAP_PORT);
                break;
            case AF_INET6:
                ((struct sockaddr_in6 *)reversed->ai_addr)->sin6_port = htons(tflag ? IMAP_TLS_PORT : IMAP_PORT);
                break;
            default:
                errorPrint("Unknown ai_family: %d", addr->ai_family);
                continue;
        }
        debugPrint("Attempting to connect to the server");
        connected = connect(sock, reversed->ai_addr, reversed->ai_addrlen);
        if (connected < 0) {
            warningPrint("Failed to connect: %s", strerror(errno));
            close(sock);
            continue;
        }
        break;
    }
    if(connected == -1)
    {
        errorPrint("Failed to connect to the server: %s", server_name);
        return 1;
    }
    infoPrint("Connection established to the server: %s", server_name);

    return 0;
}