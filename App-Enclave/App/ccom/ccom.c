#include "ccom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int create_client_socket() {
    int client_fd;

    // Create socket
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error("socket creation failed");
    }

    return client_fd;
}

void connect_to_server(int client_fd) {
	//usleep(100000);
    struct sockaddr_in serv_addr;

    // Set server address and port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to server
    if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("connection failed");
    }
}

void close_client_socket(int client_fd) {
    // Close the socket
    close(client_fd);
}

void send_data_to_server(void* data, size_t data_len) {
    int client_fd;
    ssize_t total_sent = 0;

    while (total_sent < data_len) {
        client_fd = create_client_socket();
        connect_to_server(client_fd);

        //printf("Sending %ld bytes\n", data_len - total_sent);
        ssize_t sent = write(client_fd, (char*)data + total_sent, data_len - total_sent);
        if (sent == -1) {
            perror("Write error");
            close(client_fd);
            // handle error more robustly as needed
            break;
        }
        total_sent += sent;
        //printf("Sent %ld bytes\n", sent);

        // Wait for acknowledgment from server
        char ack[4];
        if (read(client_fd, ack, sizeof(ack)) <= 0) {
            perror("Ack read error");
            close(client_fd);
            // handle error more robustly as needed
            break;
        }

        close(client_fd);
    }
}

void* receive_data_from_server(size_t data_len) {
    int client_fd = create_client_socket();
    connect_to_server(client_fd);
    
    void* data = malloc(data_len);
    if (data == NULL) {
        perror("Failed to allocate memory");
        close(client_fd);
        return NULL;
    }
    
    ssize_t total_received = 0;
    while (total_received < data_len) {
        ssize_t received = read(client_fd, (char*)data + total_received, data_len - total_received);
        if (received == -1) {
            perror("Read error");
            free(data);
            close(client_fd);
            return NULL;
        } else if (received == 0) {
            // Server closed the connection, handle end of stream
            printf("Server closed the connection early.\n");
            free(data);
            close(client_fd);
            return NULL;
        }
        total_received += received;
    }

    // Data received successfully, send an acknowledgment
    const char* ack = "ACK";
    if (write(client_fd, ack, strlen(ack)) < 0) {
        perror("Failed to send acknowledgment");
        // Decide whether to treat this as a fatal error or not
    }

    close(client_fd);

    if (total_received != data_len) {
        free(data);
        return NULL;
    }
    return data;
}
