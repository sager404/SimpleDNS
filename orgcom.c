#include "dns.h"
#include "root.h"
#include "server.h"
#include "socket.h"

int main() {
    int sock;
    struct sockaddr_in orgcomAddr;
    struct sockaddr_in localAddr;
    unsigned int serAddrLen;
    unsigned char packetIn[BUFSIZE];
    unsigned char packetOut[BUFSIZE];
    int recvMsgSize;
    int outMsgSize;
    char *file = "orgcom.txt";

    init_addr(&orgcomAddr, TLD1_SERVER_IP);
    sock = tcp_socket();
    server_bind(sock, &orgcomAddr);
    tcp_listen(sock);

    while (1) {
        int client_sock = tcp_accept(sock, &localAddr);
        tcp_receive(client_sock, packetIn);

        //接受的结构体
        dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));
        dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));

        //解析
        char *i = packetIn;
        int header_len = deserialize_header(i + 2, recvHead);
        int query_len = deserialize_query(i + 2 + header_len, recvQuery);
        printf("The domain name is: %s\n", recvQuery->name);

        memcpy(packetOut, packetIn, BUFSIZE);
        dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));
        dns_header *resHead = (struct DNS_Header *)(packetOut + 2);
        unsigned short q_len =
            parse_query_packet(packetOut + 2, resHead, resQuery);
        unsigned short len = 14;
        if (load_data(packetOut, resQuery, &len, file)) {
            resHead->flags = htons(FLAGS_RESPONSE);
            short n_len = htons(len);
            memcpy(packetOut, &n_len, 2);
            tcp_send(client_sock, packetOut, len);
        } else {
            short n_len = htons(q_len);
            memcpy(packetOut, &n_len, 2);
            resHead->flags = htons(FLAGS_NOTFOUND);
            tcp_send(client_sock, packetOut, q_len + 2);
        }
        struct Trace trace = {0};
        trace.send_ip = inet_addr(SCD1_SERVER_IP);
        trace.send_port = htons(DNS_PORT);
        trace.recv_ip = inet_addr(LOCAL_SERVER_IP);
        trace.recv_port = htons(SENDER_PORT);
        print_trace(&trace);
        close(client_sock);
        close(client_sock);
    }
    close(sock);
}
