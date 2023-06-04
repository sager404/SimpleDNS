#include "client.h"
#include "dns.h"
#include "server.h"
#include "socket.h"
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    struct sockaddr_in client_addr;
    init_addr(&client_addr, CLIENT_IP);
    struct sockaddr_in local_server_addr;
    init_addr(&local_server_addr, LOCAL_SERVER_IP);
    struct sockaddr_in root_server_addr;
    init_addr(&root_server_addr, ROOT_SERVER_IP);

    int sock = udp_socket();

    char packet[BUFSIZE] = {0};
    char query_packet[BUFSIZE] = {0};

    unsigned int client_addr_len = sizeof(client_addr);
    server_bind(sock, &local_server_addr);
    udp_receive(sock, &client_addr, query_packet);
    struct DNS_Header *header = (struct DNS_Header *)query_packet;
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));
    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));

    short offset = parse_query_packet(query_packet, header, query);
    char data[127] = {0};
    if (get_local_cache(query, rr)) {
        printf("%s", query->name);
        memcpy(packet, query_packet, BUFSIZE);
        short len = add_rr(packet + offset, rr);
        gen_response_packet(packet, header, 1);
        udp_send(sock, &client_addr, packet, offset + len);
        free(rr);
    } else {
        close(sock);
        gen_tcp_packet(query_packet, offset);
        free(rr);
        sock = tcp_socket();
        server_bind(sock, &local_server_addr);

        tcp_connect(sock, &root_server_addr);
        tcp_send(sock, query_packet, offset + 2);

        for (int i = 0; i < 3; i++) {
            memset(packet, 0, BUFSIZE);
            tcp_receive(sock, packet);
            header = (struct DNS_Header *)(packet + 2);
            if (header->answerNum == 0) {
                if (header->authorNum != 0) {
                    for (int i = 0; i < header->authorNum; i++) {
                        free(rr);
                        offset += parse_rr(packet + offset, rr);
                    }
                    for (int i = 0; i < header->addNum; i++) {
                        free(rr);
                        offset += parse_rr(packet + offset, rr);
                    }
                    char ns_addr[16] = {0};
                    parse_addr(ns_addr, rr->rdata);
                    struct sockaddr_in ns;
                    init_addr(&ns, ns_addr);
                    tcp_connect(sock, &ns);
                    send(sock, query_packet, BUFSIZE, 0);
                }
            } else {
                close(sock);
                int len = cal_packet_len(packet);
                gen_udp_packet(packet, len);
                sock = udp_socket();
                if (bind(sock, (struct sockaddr *)&local_server_addr,
                         sizeof(local_server_addr)) < 0) {
                    perror("local_server: bind failed");
                }
                sendto(sock, packet, BUFSIZE, 0,
                       (struct sockaddr *)&client_addr, client_addr_len);
                break;
            }
        }
    }
    close(sock);
}
