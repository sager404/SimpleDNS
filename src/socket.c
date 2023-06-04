#include "socket.h"

void server_bind(int sock, struct sockaddr_in *addr) {
    if (bind(sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0) {
        perror("server: bind failed");
    }
}

int udp_socket() {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("client: socket failed");
        close(sock);
    }
    return sock;
}

void udp_send(int sock, struct sockaddr_in *dest_addr, char *buffer,
              size_t buffer_len) {
    if (sendto(sock, buffer, buffer_len, 0, (struct sockaddr *)dest_addr,
               sizeof(struct sockaddr_in)) != buffer_len) {
        perror("client: sendto failed");
    }
}

void udp_receive(int sock, struct sockaddr_in *client_addr, char *buffer) {
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    if (recvfrom(sock, buffer, BUFSIZE, 0, (struct sockaddr *)client_addr,
                 &client_addr_len) < 0) {
        perror("local_server: Receive from client failed");
    }
}

int tcp_socket() {
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("client: socket failed");
        close(sock);
    }
    return sock;
}

void tcp_connect(int sock, struct sockaddr_in *dest_addr) {
    if (connect(sock, (struct sockaddr *)dest_addr,
                sizeof(struct sockaddr_in)) == -1) {
        perror("client: failed to connect to server");
        exit(EXIT_FAILURE);
    }
}

void tcp_listen(int sock) {
    if (listen(sock, LISTEN_BACKLOG) == -1) {
        perror("server: failed to listen");
        exit(EXIT_FAILURE);
    }
}

int tcp_accept(int sock, struct sockaddr_in *client_addr) {
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    int client_sock =
        accept(sock, (struct sockaddr *)client_addr, &client_addr_len);
    if (client_sock == -1) {
        perror("Failed to accept");
        exit(EXIT_FAILURE);
    }
    return client_sock;
}

void tcp_send(int client_sock, char *buffer, size_t buffer_len) {
    if (send(client_sock, buffer, buffer_len, 0) != buffer_len) {
        perror("client: send failed");
    }
}

ssize_t tcp_receive(int client_sock, char *buffer) {
    ssize_t rlen = recv(client_sock, buffer, BUFSIZE, 0);
    if (rlen == -1) {
        perror("server: receive failed");
        exit(EXIT_FAILURE);
    } else if (rlen == 0) {
        printf("server: client disconnected\n");
    }
    return rlen;
}