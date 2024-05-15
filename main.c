#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#define ERROR  "\x1B[31m"
#define SUCCESS  "\x1B[32m"
#define WARNING  "\x1B[33m"
#define DEBUG  "\x1B[34m"
#define NORMAL  "\x1B[0m"
#define INFO "\x1B[35m"
#define IMAP_PORT 143
#define IMAP_TLS_PORT 993
#define END_OF_PACKET "\r\n"
#define CHUNK_SIZE 1024

void debug_print(const char *format, ...);
void warning_print(const char *format, ...);
void error_print(const char *format, ...);
void info_print(const char *format, ...);
void print_usage();
struct addrinfo* reverse_addrinfo(struct addrinfo* head);
void debug_print(const char *format, ...) {
#ifndef NDEBUG
    va_list args;
    va_start(args, format);
    printf("%s[DEBUG]", DEBUG);
    vprintf(format, args);
    va_end(args);
    printf("%s\n", NORMAL);
#endif
}
void warning_print(const char *format, ...)
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
void error_print(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%s[ERROR]", ERROR);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s\n", NORMAL);
}
void info_print(const char *format, ...) {
#ifndef NDEBUG
    va_list args;
    va_start(args, format);
    printf("%s[INFO]", INFO);
    vprintf(format, args);
    va_end(args);
    printf("%s\n", NORMAL);
#endif
}
void print_usage() {
    fprintf(stderr, "Usage: fetchmail -u <username> -p <password> [-f <folder>] [-n <messageNum>] [-t] <command> <server_name>\n");
}
struct addrinfo* reverse_addrinfo(struct addrinfo* head) {
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
void parse_args(int argc, char *argv[], char **username, char **password, char **folder, char **messageNum, char **command, char **server_name, int *tflag, int *fflag);
void parse_args(const int argc, char *argv[], char **username, char **password, char **folder, char **messageNum, char **command, char **server_name, int *tflag, int *fflag) {
    int opt;
    while ((opt = getopt(argc, argv, "u:p:f:n:t")) != -1) {
        switch (opt) {
        case 'u':
            *username = optarg;
            break;
        case 'p':
            *password = optarg;
            break;
        case 'f':
            if (strchr(optarg, ' ') != NULL) { // Folder name contains space, needs to be quoted
                *folder = malloc(strlen(optarg) + 3); // Allocate memory for quotes and null terminator
                if (*folder == NULL) {
                    perror("Failed to allocate memory");
                    exit(EXIT_FAILURE);
                }
                sprintf(*folder, "\"%s\"", optarg); // Surround the folder name with quotes
                *fflag = 1;
            } else {
                *folder = optarg;
            }
            break;
            break;
        case 'n':
            *messageNum = optarg;
            break;
        case 't':
            *tflag = 1;
            break;
        default:
            error_print("Invalid argument provided");
            print_usage();
            exit(EXIT_FAILURE);
        }
    }
    if (optind < argc) {
        *command = argv[optind++];
        *server_name = argv[optind];
    }
}
char* base64_encode(const char *data, size_t inputLength);
char* base64_encode(const char *data, const size_t inputLength)
{
    const int outputLength = 1 + (inputLength + 2) / 3 * 4;
    char *output = calloc(outputLength, sizeof(char));
    const int outlen = EVP_EncodeBlock((unsigned char *)output, (unsigned char *)data, inputLength);
    if(outlen == -1)
    {
        error_print("Failed to b64 encode :%s | %s",data, strerror(errno));
        free(output);
        return NULL;
    }
    return output;
}
char *generate_imap_tag();
char *generate_imap_tag() {
    static int tag_count = 0;
    static char tag_buffer[20];
    tag_count++;
    sprintf(tag_buffer, "A%03d", tag_count);
    return tag_buffer;
}
char* returnFinalResponse(char* response);
char* returnFinalResponse(char* response) {
    char *responseEnd = strrchr(response, '\r');
    if (responseEnd != NULL) {
        *responseEnd = '\0';
        char *lastCarriage = strrchr(response, '\r');
        *responseEnd = '\r'; // fix original response
        if(lastCarriage != NULL){
            return lastCarriage + 2;
        }
    }
    return response;
}
char* full_recv(int sock, int tf, const char* tag) ;
char* full_recv(const int sock, const int tf, const char* tag) {
    char buffer[CHUNK_SIZE];
    char *data = malloc(1);
    int received;
    int total_received = 0;
    while((received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[received] = '\0';
        char *temp = realloc(data, total_received + received + 1);
        if (temp == NULL) {
            free(data);
            fprintf(stderr, "Memory allocation failed\n");
            return NULL;
        }
        memset(temp + total_received, 0, received + 1); //have to initialize realloced heap or valgrind will complain
        data = temp;
        memcpy(data + total_received, buffer, received);
        total_received += received;
        const char* dataFinal = returnFinalResponse(data);
        if (tf == 0) {
            // Non-tagged response check
            if (strncmp(dataFinal, "* OK", 4) == 0 ||
                strncmp(dataFinal, "* BAD", 5) == 0 ||
                strncmp(dataFinal, "* NO", 4) == 0) {
                if(strstr(buffer, "\r\n") != NULL) {
                    break;
                }
            }
        } else if (tf == 1) {
            if (strncmp(dataFinal, tag, strlen(tag)) == 0) {
                if (strncmp(dataFinal + strlen(tag) + 1, "OK", 2) == 0 ||
                    strncmp(dataFinal + strlen(tag) + 1, "BAD", 3) == 0 ||
                    strncmp(dataFinal + strlen(tag) + 1, "NO", 2) == 0) {
                    if(strstr(buffer, "\r\n") != NULL) {
                        break;
                    }
                }
            }
        }
    }
    if (received < 0) {
        free(data);
        return NULL;
    }
    if (data != NULL) {
        data[total_received] = '\0';
    }
    debug_print("RECV: %s", data);
    return data;
}
char* parse_imap_response(const char* response);
char* parse_imap_response(const char* response) {
    const char* start = strstr(response, "{")+strlen("{");
    const char* end = strchr(response, '}');
    const int length = end - start;
    char* bufferSizeStr = NULL;
    int bufferSize = 0;
    if (start < end) {
        bufferSizeStr = (char*) malloc(length + 1);
        if (bufferSizeStr != NULL) {
            strncpy(bufferSizeStr, start, length);
            bufferSizeStr[length] = '\0';
            bufferSize = atoi(bufferSizeStr);
            free(bufferSizeStr);
            if(bufferSize == 0){
                warning_print("No email in body");
            }
        } else {
            error_print("Memory allocation failed");
            return NULL;
        }
    }
    else{
        error_print("The required substring could not be found");
        return NULL;
    }
    char* result = (char*)malloc(bufferSize + 1);
    if (result != NULL) {
        memcpy(result, end + 3, bufferSize); //have to account for } and \r\n
        (result)[bufferSize-1] = '\0'; //remove /n only cannot remove /r else no match
        return result;
    } else {
        error_print("Memory allocation failed");
        return NULL;
    }
}
void removeCRLF(char *str);
void removeCRLF(char *str) {
    const char *src = str;
    char*dst = str;
    while (*src != '\0') {
        if (*src == '\r' && *(src + 1) == '\n') {
            src += 2;  // Skip the \r\n characters
        } else {
            *dst++ = *src++;  // Copy the character
        }
    }
    *dst = '\0';  // Null-terminate the modified string
}
int imap_authenticate_plain(int sock, const char *username, const char *password);
int imap_authenticate_plain(const int sock, const char *username, const char *password) {
    const size_t ulen = strlen(username);
    const size_t plen = strlen(password);
    const size_t total_length = ulen + plen + 2;
    char *auth_string = malloc(total_length + 1);
    if (auth_string == NULL) {
        error_print("Memory allocation failed for auth_string");
        return -1;
    }
    auth_string[0] = '\0';
    memcpy(auth_string + 1, username, ulen);
    auth_string[ulen + 1] = '\0';
    memcpy(auth_string + ulen + 2, password, plen);
    char *encoded = base64_encode(auth_string, total_length);
    free(auth_string);
    if (encoded == NULL) {
        debug_print("Failed to encode authentication string");
        return -1;
    }
    debug_print("Encoded login string: %s", encoded);
    const char* tag = generate_imap_tag();
    char *command = malloc(strlen(tag) + strlen(encoded) + strlen(" AUTHENTICATE PLAIN ") + strlen(END_OF_PACKET) + 1);
    if (command == NULL) {
        error_print("Memory allocation failed for command");
        free(encoded);
        return -1;
    }
    sprintf(command, "%s AUTHENTICATE PLAIN %s%s", tag ,encoded, END_OF_PACKET);
    free(encoded);
    debug_print("Sending command: %s", command);
    const int sent = send(sock, command, strlen(command), 0);
    free(command);
    if (sent < 0){
        error_print("Failed to send authentication command");
        return -1;
    }
    char *response = full_recv(sock, 1, (char*)tag);
    if(response == NULL)
    {
        error_print("Failed to receive data from the server");
        return -1;
    }
    int result = -1; // Default to failure
    const char* finalResponse = returnFinalResponse(response);
    if (strncmp(finalResponse, tag, strlen(tag)) == 0 && strncmp(finalResponse + strlen(tag) + 1, "OK", 2) == 0) {
        debug_print("Authentication successful.");
        result = 0;  // Success
    } else {
        error_print("Authentication failed.");
    }

    info_print("%s", response);
    free(response);
    return result;
}
int imap_select_folder(int sock, const char *folder);
int imap_select_folder(const int sock, const char *folder)
{
    if(folder == NULL)
    {
        error_print("Folder name is required");
        return -1;
    }
    const char *tag = generate_imap_tag();
    char *command = malloc(strlen(tag) + strlen(" SELECT ") + strlen(folder) + strlen(END_OF_PACKET) + 1);
    if (command == NULL) {
        error_print("Memory allocation failed for command");
        return -1;
    }
    sprintf(command, "%s SELECT %s%s", tag, folder, END_OF_PACKET);
    debug_print("Sending command: %s", command);
    const int sent = send(sock, command, strlen(command), 0);
    free(command);
    if (sent < 0) {
        error_print("Failed to send SELECT command");
        return -1;
    }
    char *response = full_recv(sock, 1, (char*)tag);
    if(response == NULL)
    {
        error_print("Failed to receive data from the server");
        return -1;
    }
    int result = -1; // Default to failure
    const char* finalResponse = returnFinalResponse(response);

    if (strncmp(finalResponse, tag, strlen(tag)) == 0 && strncmp(finalResponse + strlen(tag) + 1, "OK", 2) == 0) {
        debug_print("Folder selection successful");
        result = 0; // Successful folder selection
    }
    info_print("%s", response);
    free(response);
    return result;
}
int imap_fetch_message(int sock, const char *messageNum, char **email);
int imap_fetch_message(const int sock, const char *messageNum, char **email) {
    const char *tag = generate_imap_tag();
    char *command = malloc(strlen(tag) + strlen(" FETCH ") + strlen(messageNum) + strlen(" BODY.PEEK[]") + strlen(END_OF_PACKET) + 1);
    if (command == NULL) {
        error_print("Memory allocation failed for command");
        return -1;
    }
    sprintf(command, "%s FETCH %s BODY.PEEK[]%s", tag, messageNum, END_OF_PACKET);
    debug_print("Sending command: %s", command);
    const int sent = send(sock, command, strlen(command), 0);
    free(command);
    if (sent < 0) {
        error_print("Failed to send FETCH command");
        return -1;
    }
    char *response = full_recv(sock, 1, (char*)tag);
    if(response == NULL)
    {
        error_print("Failed to receive data from the server");
        return -1;
    }
    int result = -1; // Default to failure
    const char* finalResponse = returnFinalResponse(response);
    if (strncmp(finalResponse, tag, strlen(tag)) == 0 && strncmp(finalResponse + strlen(tag) + 1, "OK", 2) == 0) {
        debug_print("Message fetch successful");
        *email = parse_imap_response(response);
        if(*email == NULL)
        {
            error_print("Failed to parse the response");
            return result;
        }
        result = 0; // Successful message fetch
    }
    info_print("%s", response);
    free(response);
    return result;
}
int imap_fetch_message_header_to(int sock, const char *messageNum, char **header);
int imap_fetch_message_header_to(const int sock, const char *messageNum, char **header)
{
    int result = -1;
    const char *tag = generate_imap_tag();
    char *command = malloc(strlen(tag) + strlen(" FETCH ") + strlen(messageNum) + strlen(" BODY.PEEK[HEADER.FIELDS (TO)]") + strlen(END_OF_PACKET) + 1);
    if (command == NULL) {
        error_print("Memory allocation failed for command");
        return result;
    }
    sprintf(command, "%s FETCH %s BODY.PEEK[HEADER.FIELDS (TO)]%s", tag, messageNum, END_OF_PACKET);
    debug_print("Sending command: %s", command);
    const int sent = send(sock, command, strlen(command), 0);
    free(command);
    if (sent < 0) {
        error_print("Failed to send FETCH command");
        return result;
    }
    char *response = full_recv(sock, 1, (char*)tag);
    if(response == NULL)
    {
        error_print("Failed to receive data from the server");
        return result;
    }
    const char* finalResponse = returnFinalResponse(response);
    if (strncmp(finalResponse, tag, strlen(tag)) == 0 && strncmp(finalResponse + strlen(tag) + 1, "OK", 2) == 0) {
        debug_print("Message fetch successful");
        *header = parse_imap_response(response);
        if(*header == NULL)
        {
            error_print("Failed to parse the response");
            return result;
        }
        result = 0; // Successful message fetch
    }
    removeCRLF(*header);
    info_print("%s", response);
    free(response);
    return result;
}
int imap_fetch_message_header_from(int sock, const char *messageNum, char **header);
int imap_fetch_message_header_from(const int sock, const char *messageNum, char **header)
{
    int result = -1;
    const char *tag = generate_imap_tag();
    char *command = malloc(strlen(tag) + strlen(" FETCH ") + strlen(messageNum) + strlen(" BODY.PEEK[HEADER.FIELDS (FROM)]") + strlen(END_OF_PACKET) + 1);
    if (command == NULL) {
        error_print("Memory allocation failed for command");
        return result;
    }
    sprintf(command, "%s FETCH %s BODY.PEEK[HEADER.FIELDS (FROM)]%s", tag, messageNum, END_OF_PACKET);
    debug_print("Sending command: %s", command);
    const int sent = send(sock, command, strlen(command), 0);
    free(command);
    if (sent < 0) {
        error_print("Failed to send FETCH command");
        return result;
    }
    char *response = full_recv(sock, 1, (char*)tag);
    if(response == NULL)
    {
        error_print("Failed to receive data from the server");
        return result;
    }
    const char* finalResponse = returnFinalResponse(response);
    if (strncmp(finalResponse, tag, strlen(tag)) == 0 && strncmp(finalResponse + strlen(tag) + 1, "OK", 2) == 0) {
        debug_print("Message fetch successful");
        *header = parse_imap_response(response);
        if(*header == NULL)
        {
            error_print("Failed to parse the response");
            return result;
        }
        result = 0; // Successful message fetch
    }
    removeCRLF(*header);
    info_print("%s", response);
    free(response);
    return result;
}
int imap_fetch_message_header_date(int sock, const char *messageNum, char **header);
int imap_fetch_message_header_date(const int sock, const char *messageNum, char **header)
{
    int result = -1;
    const char *tag = generate_imap_tag();
    char *command = malloc(strlen(tag) + strlen(" FETCH ") + strlen(messageNum) + strlen(" BODY.PEEK[HEADER.FIELDS (DATE)]") + strlen(END_OF_PACKET) + 1);
    if (command == NULL) {
        error_print("Memory allocation failed for command");
        return result;
    }
    sprintf(command, "%s FETCH %s BODY.PEEK[HEADER.FIELDS (DATE)]%s", tag, messageNum, END_OF_PACKET);
    debug_print("Sending command: %s", command);
    const int sent = send(sock, command, strlen(command), 0);
    free(command);
    if (sent < 0) {
        error_print("Failed to send FETCH command");
        return result;
    }
    char *response = full_recv(sock, 1, (char*)tag);
    if(response == NULL)
    {
        error_print("Failed to receive data from the server");
        return result;
    }
    const char* finalResponse = returnFinalResponse(response);
    if (strncmp(finalResponse, tag, strlen(tag)) == 0 && strncmp(finalResponse + strlen(tag) + 1, "OK", 2) == 0) {
        debug_print("Message fetch successful");
        *header = parse_imap_response(response);
        if(*header == NULL)
        {
            error_print("Failed to parse the response");
            return result;
        }
        result = 0; // Successful message fetch
    }
    removeCRLF(*header);
    info_print("%s", response);
    free(response);
    return result;
}
int imap_fetch_message_header_subject(int sock, const char *messageNum, char **header);
int imap_fetch_message_header_subject(const int sock, const char *messageNum, char **header)
{
    int result = -1;
    const char *tag = generate_imap_tag();
    char *command = malloc(strlen(tag) + strlen(" FETCH ") + strlen(messageNum) + strlen(" BODY.PEEK[HEADER.FIELDS (SUBJECT)]") + strlen(END_OF_PACKET) + 1);
    if (command == NULL) {
        error_print("Memory allocation failed for command");
        return result;
    }
    sprintf(command, "%s FETCH %s BODY.PEEK[HEADER.FIELDS (SUBJECT)]%s", tag, messageNum, END_OF_PACKET);
    debug_print("Sending command: %s", command);
    const int sent = send(sock, command, strlen(command), 0);
    free(command);
    if (sent < 0) {
        error_print("Failed to send FETCH command");
        return result;
    }
    char *response = full_recv(sock, 1, (char*)tag);
    if(response == NULL)
    {
        error_print("Failed to receive data from the server");
        return result;
    }
    const char* finalResponse = returnFinalResponse(response);
    if (strncmp(finalResponse, tag, strlen(tag)) == 0 && strncmp(finalResponse + strlen(tag) + 1, "OK", 2) == 0) {
        debug_print("Message fetch successful");
        *header = parse_imap_response(response);
        if(*header == NULL)
        {
            error_print("Failed to parse the response");
            return result;
        }
        result = 0; // Successful message fetch
    }
    removeCRLF(*header);
    info_print("%s", response);
    free(response);
    return result;
}
int imap_fetch_message_header(int sock, const char *messageNum, char **header);
int imap_fetch_message_header(const int sock, const char *messageNum, char **header)
{
    char *to = NULL, *from = NULL, *date = NULL, *subject = NULL;
    imap_fetch_message_header_to(sock, messageNum, &to);
    imap_fetch_message_header_from(sock, messageNum, &from);
    imap_fetch_message_header_date(sock, messageNum, &date);
    imap_fetch_message_header_subject(sock, messageNum, &subject);
    if (!to || !from || !date || !subject) {
        if (to) free(to);
        if (from) free(from);
        if (date) free(date);
        if (subject) free(subject);
        return -1;
    }
    // BUG FIX
    if (to[strlen(to) - 1] == '\r') to[strlen(to) - 1] = '\0';
    if (from[strlen(from) - 1] == '\r') from[strlen(from) - 1] = '\0';
    if (date[strlen(date) - 1] == '\r') date[strlen(date) - 1] = '\0';
    if (subject[strlen(subject) - 1] == '\r') subject[strlen(subject) - 1] = '\0';
    const char *fromattedTo = strchr(to, ':');
    const char *fromattedFrom = strchr(from, ':');
    const char *fromattedDate = strchr(date, ':');
    if (fromattedTo == NULL)
        fromattedTo = to;
    else
        fromattedTo++;
    if (fromattedFrom == NULL)
        fromattedFrom = to;
    else
        fromattedFrom++;
    if (fromattedDate == NULL)
        fromattedDate = to;
    else
        fromattedDate++;
    const char *formattedSubject = strchr(subject, ':');
    if(strlen(subject) > 0 && formattedSubject != NULL)
        formattedSubject++;
    else
        formattedSubject = " <No subject>";
    // Calculate total length for final header, 5 = 4\n and 1\0
    const size_t length = strlen("From:")+strlen(fromattedTo) + strlen("To:")+strlen(fromattedFrom) +strlen("Date:")+ strlen(fromattedDate) + strlen("Subject:") + strlen(formattedSubject) + 5;
    *header = malloc(length);
    if (*header == NULL) {
        free(to); free(from); free(date); free(subject);
        return -1;
    }
    // Format the final header string
    snprintf(*header, length, "From:%s\nTo:%s\nDate:%s\nSubject:%s", fromattedFrom, fromattedTo, fromattedDate, formattedSubject);
    // Cleanup
    free(to);
    free(from);
    free(date);
    free(subject);
    debug_print(*header);
    return 0;
}
int mime_parse(char* content, char** mime);
int mime_parse(char* content, char** mime)
{
    // find the start of mime
    const char* mimeStart = strstr(content, "Content-Type: text/plain; charset=UTF-8");
    if(mimeStart == NULL)
    {
        return 4;
    }
    printf("%s",content);
    return 0;
}
int main(const int argc, char **argv)
{
    char *username = NULL, *password = NULL, *folder = NULL, *messageNum = NULL, *command = NULL, *server_name = NULL;
    int tflag = 0, fflag = 0;
    parse_args(argc, argv, &username, &password, &folder, &messageNum, &command, &server_name, &tflag, &fflag);
    if (username == NULL|| password == NULL) {
        error_print("Username and password are required");
        print_usage();
        exit(EXIT_FAILURE);
    }
    if (command == NULL|| server_name == NULL) {
        error_print("Command and server name are required");
        print_usage();
        exit(EXIT_FAILURE);
    }
#ifndef NDEBUG
    //info_print("Username: %s", username);
    //info_print("Password: %s", password);
    //info_print("Folder: %s", folder);
    //info_print("Message Number: %s", messageNum);
    //info_print("Command: %s", command);
    //info_print("Server Name: %s", server_name);
    //info_print("TLS Flag: %d", tflag);
    //info_print("Command: %s", command);
#endif
    struct addrinfo *result = 0;
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    debug_print("Attempting to resolve IPs for %s", server_name);
    server_name = "localhost";
    if (getaddrinfo(server_name, NULL, &hints, &result)){
        error_print("getaddrinfo failed to resolve: %s", strerror(errno));
        return 1;
    }
    if(result == NULL){
        error_print("Failed to get address info");
        return 1;
    }
    const struct addrinfo *reversed = reverse_addrinfo(result);
    if(reversed->ai_family != AF_INET && reversed->ai_family != AF_INET6)
    {
        error_print("Unknown ai_family: %d", reversed->ai_family);
        return 1;
    }
    int sock = -1;
    int connected = -1;
    int fallback = 0;
    for(const struct addrinfo *addr = reversed; addr != NULL; addr = addr->ai_next)
    {
        debug_print("Attemping to creating Socket");
        sock = socket(reversed->ai_family, reversed->ai_socktype, reversed->ai_protocol);
        if (sock < 0) {
            warning_print("Socket creation failed: %s", strerror(errno));
            continue;
        }
        debug_print("Socket created successfully");
        debug_print("Setting IMAP port of sockaddr: %d", tflag ? IMAP_TLS_PORT : IMAP_PORT);
        switch (addr->ai_family)
        {
            case AF_INET:
                if(fallback == 0)
                {
                    warning_print("Failed to connect via IPV6 falling back to IPV4");
                    fallback = 1;
                }
                ((struct sockaddr_in *)reversed->ai_addr)->sin_port = htons(tflag ? IMAP_TLS_PORT : IMAP_PORT);
                break;
            case AF_INET6:
                ((struct sockaddr_in6 *)reversed->ai_addr)->sin6_port = htons(tflag ? IMAP_TLS_PORT : IMAP_PORT);
                break;
            default:
                error_print("Unknown ai_family: %d", addr->ai_family);
                continue;
        }
        debug_print("Attempting to connect to the server");
        connected = connect(sock, reversed->ai_addr, reversed->ai_addrlen);
        if (connected < 0) {
            warning_print("Failed to connect: %s", strerror(errno));
            close(sock);
            continue;
        }
        break;
    }
    if(connected == -1)
    {
        error_print("Failed to connect to the server: %s", server_name);
        return 1;
    }
    info_print("Connection established to the server: %s", server_name);
    char* serverReady = full_recv(sock, 0, NULL);
    if(serverReady == NULL)
    {
        error_print("Failed to receive data from the server");
        return 1;
    }
    info_print("Server ready: %s", serverReady);
    free(serverReady);
    debug_print("Attempting to authenticate with SASL PLAIN");
    if(imap_authenticate_plain(sock, username, password) != 0)
    {

        printf("Login failure\n");
        close(sock);
        freeaddrinfo(result);
        return 1;
    }
    if(imap_select_folder(sock, folder) != 0)
    {
       // printf("Folder not found\n");
        //close(sock);
        //freeaddrinfo(result);
        //return 1;
    }
    if(strcmp(command, "retrieve") == 0)
    {
        char* email = NULL;
        if(imap_fetch_message(sock, messageNum, &email) != 0)
        {
            printf("Message not found\n");
            close(sock);
            freeaddrinfo(result);
            return 1;
        }
        printf("%s\n",email);
        free(email);
    }
    if(strcmp(command, "parse") == 0)
    {
        char* header = NULL;
        if(imap_fetch_message_header(sock, messageNum, &header) != 0)
        {
            printf("Header not found\n");
            close(sock);
            freeaddrinfo(result);
            return 1;
        }
        printf("%s\n",header);
        free(header);
    }
    if(strcmp(command, "mime") == 0)
    {
        char* email = NULL;
        char* mime = NULL;
        if(imap_fetch_message(sock, messageNum, &email) != 0)
        {
            printf("Message not found\n");
            close(sock);
            freeaddrinfo(result);
            return 1;
        }
        int i;
        if((i = mime_parse(email, &mime) != 0))
        {
            close(sock);
            freeaddrinfo(result);
            if(i == 4)
            {
                error_print("Failed to parse MIME, UTF-8 text/plain part not found ");
            }
            else
            {
                error_print("Failed to parse MIME, GENERIC");
            }
            return i;
        }
        free(email);
    }
    close(sock);
    freeaddrinfo(result);
    return 0;
}