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
    struct sockaddr_in recv_addr;
    init_addr(&recv_addr, LOCAL_SERVER_IP);
    struct sockaddr_in send_addr;
    init_sender_addr(&send_addr, LOCAL_SERVER_IP);
    struct sockaddr_in root_server_addr;
    init_addr(&root_server_addr, ROOT_SERVER_IP);

    int sock = udp_socket();
    int tcp_sock;

    char packet[BUFSIZE] = {0};
    char query_packet[BUFSIZE] = {0};

    server_bind(sock, &recv_addr);
    udp_receive(sock, &client_addr, query_packet);
    struct DNS_Header *header = (struct DNS_Header *)query_packet;
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));

    short offset = parse_query_packet(query_packet, header, query);
    short query_len = offset;
    char data[127] = {0};
    memcpy(packet, query_packet, BUFSIZE);
    if (get_local_cache(packet, query, offset)) {
        printf("%s", query->name);
        header = (struct DNS_Header *)packet;
        header->flags = htons(FLAGS_RESPONSE);
        // gen_response_packet(packet, header, 1);
        unsigned short len = cal_packet_len(packet);
        udp_send(sock, &client_addr, packet, len);
    } else {
        struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
        gen_tcp_packet(query_packet, offset);

        tcp_sock = tcp_socket();
        server_bind(tcp_sock, &send_addr);
        tcp_connect(tcp_sock, &root_server_addr);
        tcp_send(tcp_sock, query_packet, offset + 2);

        while (1) {
            memset(packet, 0, BUFSIZE);

            tcp_receive(sock, packet);
            header = (struct DNS_Header *)(packet + 2);

            if (ntohs(header->flags) == FLAGS_NOTFOUND) {
                int len = cal_packet_len(packet + 2);
                gen_udp_packet(packet, len);
                udp_send(tcp_sock, &client_addr, packet, len);
                break;
            }

            if (header->answerNum == 0) {
                int num = ntohs(header->authorNum) + ntohs(header->addNum);

                for (int i = 0; i < num; i++) {
                    free(rr);
                    offset += parse_rr(packet + offset, rr);
                }

                char ns_addr[16] = {0};
                parse_addr(ns_addr, rr->rdata);
                struct sockaddr_in ns;
                init_addr(&ns, ns_addr);
                tcp_connect(tcp_sock, &ns);
                tcp_send(tcp_sock, query_packet, offset);

            } else {

                int len = cal_packet_len(packet);
                gen_udp_packet(packet, len);
                header = (struct DNS_Header *)packet;
                int ans_num = ntohs(header->answerNum)+ntohs(header->addNum);
                add_local_cache(packet+query_len, ans_num);
                udp_send(sock, &client_addr, packet, len);
                break;
            }
        }
    }
    close(sock);
}
