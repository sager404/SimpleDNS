#include "root.h"
#include <stdio.h>
#include "client.h"
#include "dns.h"
#include "server.h"
#include "socket.h"

int main() {
    char qname[127] = {0};
    char qtype[127] = {0};
    char packetOut[BUFSIZE] = {0};
    char packetIn[BUFSIZE] = {0};

    struct sockaddr_in root_addr, client_addr;
    init_addr(&root_addr, ROOT_SERVER_IP);

    int sock = tcp_socket();
    server_bind(sock, &root_addr);
    tcp_listen(sock);

    struct DNS_Header *header = malloc(sizeof(struct DNS_Header));
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));

    while (1) {
        int client_sock = tcp_accept(sock, &client_addr);
        char buffer[BUFSIZE] = {0};

        ssize_t rlen = 0;
        do {
            rlen = tcp_receive(client_sock, buffer);
            int header_len = deserialize_header(buffer + 2, header);
            deserialize_query(buffer + 2 + header_len, query);
        } while (rlen);

        close(client_sock);
    }
    close(sock);
}