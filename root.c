#include "root.h"
#include <stdio.h>
#include "client.h"
#include "dns.h"
#include "server.h"

int main() {
    char qname[127] = {0};
    char qtype[127] = {0};
    char packetOut[BUFSIZE] = {0};
    char packetIn[BUFSIZE] = {0};

    struct sockaddr_in client_addr;

    int sock = tcp_socket();
    tcp_listen(sock);

    while (1) {
        int client_sock = tcp_accept(sock, &client_addr);
        char buffer[BUFSIZE] = {0};

        ssize_t rlen = 0;
        do {
            rlen = tcp_receive(sock, buffer);

        } while (rlen);

        close(sock);
    }
}