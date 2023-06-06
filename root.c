#include "root.h"
#include "client.h"
#include "dns.h"
#include "server.h"
#include "socket.h"

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
        unsigned char buffer[BUFSIZE] = {0};

        ssize_t rlen = 0;
        while (rlen = tcp_receive(client_sock, buffer)) {
            int header_len = deserialize_header(buffer + 2, header);
            deserialize_query(buffer + 2 + header_len, query);

            memset(buffer, 0, BUFSIZE);
            struct DNS_RR *RRs;
            int cnt = get_root_data(&RRs);
            unsigned short length = 0;

            int ns_idx = find_ns(RRs, cnt, query);
            if (ns_idx != -1) {
                init_header(header, header->id, 0x0000, header->queryNum, 0, 1,
                            1);
                int a_idx =
                    find_a_corresponding_ns(RRs, cnt, RRs[ns_idx].rdata);
                if (a_idx == -1) {
                    perror("Database error!");
                    exit(EXIT_FAILURE);
                }
                header->flags = htons(FLAGS_RESPONSE);
                length += gen_response(buffer + 2, header, query);
                length += add_new_rr(buffer + 2 + length, RRs + ns_idx);
                length += add_new_a_rr(buffer + 2 + length, RRs + a_idx);
                *((unsigned short *)buffer) = htons(length);
            } else {
                init_header(header, header->id, 0x0000, header->queryNum, 0, 0,
                            0);
                header->flags = htons(FLAGS_NOTFOUND);
                length += gen_response(buffer + 2, header, query);
                *((unsigned short *)buffer) = htons(length);
            }
            tcp_send(client_sock, buffer, length + 2);
            struct Trace trace = {0};
            trace.send_ip = inet_addr(SCD1_SERVER_IP);
            trace.send_port = htons(DNS_PORT);
            trace.recv_ip = inet_addr(LOCAL_SERVER_IP);
            trace.recv_port = htons(SENDER_PORT);
            print_trace(&trace);
            close(client_sock);
            break;
        }
        close(client_sock);
    }
    close(sock);
}