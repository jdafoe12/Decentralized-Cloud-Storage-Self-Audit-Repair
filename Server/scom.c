/*
 * Function definitions for socket communication interface.
 */

#include "scom.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>

void error(const char *msg) 
{
 perror(msg);
 exit(EXIT_FAILURE);
}


int create_socket() 
{
 int server_fd, opt = 1;
 struct sockaddr_in address;
 
 // Create socket file descriptor
 if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
 error("socket failed");
 }

 // Set socket options
 if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
 error("setsockopt failed");
 }

 // Bind socket to address and port
 address.sin_family = AF_INET;
 address.sin_addr.s_addr = INADDR_ANY;
 address.sin_port = htons(PORT);
 if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
 error("bind failed");
 }

 // Start listening for connections
 if(listen(server_fd, 3) < 0) {
 error("listen failed");
 }


 return server_fd;
}

int accept_connection(int server_fd) 
{
 int new_socket;
 struct sockaddr_in address;
 int addrlen = sizeof(address);

 // Wait for an accept a new connection
 //printf("Waiting for a connection...\n");
 if((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
 error("accept failed");
 }
 //printf("Connection accepted\n");


 return new_socket;
}


void send_message(int client_fd, uint8_t *message, size_t size) 
{
 // Send a message to the client
 send(client_fd, message, size, 0);
}

void close_socket(int client_fd, int server_fd) 
{
 // Close the client socket
 close(client_fd);

 // Close the server socket
 close(server_fd);
}