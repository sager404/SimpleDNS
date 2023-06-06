#include "client.h"
#include "dns.h"
#include "server.h"
#include "socket.h"
#include <netinet/in.h>
#include <time.h>

int main(int argc, char *argv[]) {
    struct sockaddr_in client_addr;
    init_addr(&client_addr, CLIENT_IP);
    struct sockaddr_in local_server_addr;
    init_addr(&local_server_addr, LOCAL_SERVER_IP);

    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "-h"))) {
        printf("Usage: ./client domain type\n");
        exit(1);
    }

    if (argc != 3) {
        printf("Wrong argument number!\n");
        exit(1);
    }

    int sock = udp_socket();

    char *qname = argv[1];
    char *qtype = argv[2];

    char packetOut[BUFSIZE] = {0};
    char packetIn[BUFSIZE] = {0};
    // memset(packetOut, 0, sizeof(packetOut));
    // memset(packetIn, 0, sizeof(packetIn));

    unsigned short type = A;
    if (!strcmp(qtype, "A")) {
        type = A;
    } else if (!strcmp(qtype, "MX")) {
        type = MX;
    } else if (!strcmp(qtype, "CNAME")) {
        type = CNAME;
    } else if (!strcmp(qtype, "PTR")) {
        type = PTR;
    }
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    struct DNS_Header *header = malloc(sizeof(struct DNS_Header));
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));
    // memset(query, 0, strlen(qname)+5);
    gen_dns_header(header, FLAGS_QUERY, 1, 0);
    gen_dns_query(query, qname, type);
    int len = gen_client_query_packet(packetOut, header, query);
    free(query->name);
    free(header);
    free(query);
    udp_send(sock, &local_server_addr, packetOut, len);
    unsigned int sock_len = 0;
    int i = 1;
    while (1) {
        udp_receive(sock, &client_addr, packetIn);
        if (packetIn[0] == 0xff) {
            char addr[16] = {0};
            parse_addr(addr, packetIn+2);
            printf("hop %d: %s\n", i, addr);
            i++;
        } else {
            struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
            header = (struct DNS_Header *)packetIn;
            printf("********** DNS Response **********\n");
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            double ms = (end_time.tv_sec - start_time.tv_sec) * 1e3 +
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e6;
            printf("*Response time:\t %.2fms\n", ms);
            if (ntohs(header->flags) == FLAGS_NOTFOUND) {
                printf("Not found!\n");
            } else {
                parse_dns_response(packetIn, rr);

                printf("*Address:\t %s\n", rr->rdata);
                free(rr->rdata);
            }
            printf("**********************************\n");
            free(rr);
            break;
        }
    }

    close(sock);
}
