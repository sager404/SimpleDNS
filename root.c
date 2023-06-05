#include "root.h"
#include "client.h"
#include "dns.h"
#include "server.h"
#include "socket.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    char qname[127] = {0};
    char qtype[127] = {0};
    char packetOut[BUFSIZE] = {0};
    char packetIn[BUFSIZE] = {0};

    struct sockaddr_in client_addr;
    struct sockaddr_in root_addr;
    init_addr(&root_addr, ROOT_SERVER_IP);

    int sock = tcp_socket();
    server_bind(sock, &root_addr);
    tcp_listen(sock);

    struct DNS_Header *header =
        (struct DNS_Header *)malloc(sizeof(struct DNS_Header));
    struct DNS_Query *query =
        (struct DNS_Query *)malloc(sizeof(struct DNS_Query));

    while (1) {
        int client_sock = tcp_accept(sock, &client_addr);
        char buffer[BUFSIZE] = {0};

        ssize_t rlen = 0;
        int header_len, query_len;
        while (rlen = tcp_receive(client_sock, buffer)) {
            header_len = deserialize_header(buffer + 2, header);
            query_len = deserialize_query(buffer + 2 + header_len, query);
        }
        memset(buffer, 0, BUFSIZE);

        struct DNS_RR *RRs;
        int cnt = get_root_data(RRs);
        int offset = 2 + header_len + query_len;
        header->answerNum = 0;
        header->authorNum = htons(1);
        header->addNum = htons(1);

        int ns_idx = find_ns(RRs, cnt, query);
        if (ns_idx != -1) {
            int a_idx = find_a_corresponding_ns(RRs, cnt, RRs[ns_idx].rdata);
            if (a_idx == -1) {
                perror("Database error!");
                exit(EXIT_FAILURE);
            }
            header->flags = htons(gen_flags(1, OP_STD, 1, R_FINE));
            gen_response(buffer, header, query);
            offset += add_rr(buffer + offset, RRs + ns_idx);
            offset += add_rr(buffer + offset, RRs + a_idx);
        } else {
            header->flags = htons(gen_flags(1, OP_STD, 1, R_NAME_ERROR));
            gen_response(buffer, header, query);
        }

        close(client_sock);
    }
    close(sock);
}