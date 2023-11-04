

#ifndef SCOM_H
#define SCOM_H

#define PORT 49200
#define BUFFER_SIZE 1024

void error(const char *msg);

int create_socket();

int accept_connection(int server_fd);

void close_socket(int client_fd, int server_fd);


#endif
