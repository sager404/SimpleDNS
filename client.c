#include "dns.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void gen_query_packet(char *packet, struct DNS_Header *header,
                      struct DNS_Query *query, char *qname);
void parse_dns_response(unsigned char *packet, struct DNS_RR *rr);

struct sockaddr_in localserver_addr;
struct sockaddr_in client_addr;
int sock;

void init_client() {

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("client: socket failed");
        close(sock);
    }

    memset(&localserver_addr, 0, sizeof(localserver_addr));
    localserver_addr.sin_family = AF_INET;
    localserver_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    localserver_addr.sin_port = htons(DNS_PORT);
}

int main() {
    init_client();
    // if (connect(sock, (struct sockaddr *)&localserver_addr,
    //             sizeof(localserver_addr)) < 1) {
    //     perror("connect failed");
    //     close(sock);
    // }
    char qname[127] = {0};
    char qtype[127] = {0};

    char packetOut[BUFSIZE] = {0};
    char packetIn[BUFSIZE] = {0};
    // memset(packetOut, 0, sizeof(packetOut));
    // memset(packetIn, 0, sizeof(packetIn));

    printf("Input the domain:\n");
    scanf("%s", qname);

    unsigned short type = A;
    // if (!strcmp(qtype, "A")) {
    //     type = A;
    // }else if (!strcmp(qtype, "MX")) {
    //     type = MX;
    // }else if (!strcmp(qtype, "NS")) {
    //     type = NS;
    // }else{
    //     printf("Invalid type!");
    // }

    struct DNS_Header *header = malloc(sizeof(struct DNS_Header));
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));
    // memset(query, 0, strlen(qname)+5);
    gen_dns_header(header, FLAGS_QUERY, 1, 0);
    gen_dns_query(query, qname, type);
    gen_query_packet(packetOut, header, query, qname);

    if (sendto(sock, packetOut, BUFSIZE, 0,
               (struct sockaddr *)&localserver_addr,
               sizeof(localserver_addr)) < 0) {
        perror("client: sendto failed");
    }
    unsigned int sock_len = 0;

    if (recvfrom(sock, packetIn, BUFSIZE, 0, (struct sockaddr *)&client_addr,
                 &sock_len) < 0) {
        perror("client: Receive from server failed");
    } else {
        struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
        parse_dns_response(packetIn, rr);
        printf("%s", rr->rdata);
        free(rr->rdata);
        free(rr);
    }

    free(query->name);
    free(header);
    free(query);
}

void gen_query_packet(char *packet, struct DNS_Header *header,
                      struct DNS_Query *query, char *qname) {
    memcpy(packet, header, sizeof(struct DNS_Header));
    int name_len = strlen(qname) + 2;
    int offset = sizeof(struct DNS_Header);
    memcpy(packet + offset, query->name, name_len);
    offset += name_len;
    memcpy(packet + offset, &query->qtype, sizeof(query->qtype));
    offset += sizeof(query->qtype);
    memcpy(packet + offset, &query->qclass, sizeof(query->qclass));
}

void parse_dns_response(unsigned char *packet, struct DNS_RR *rr) {
    int i = 0, j = 0;
    int name_len = 0;
    int offset = 0;

    i += sizeof(struct DNS_Header);
    struct DNS_Header *header = (struct DNS_Header *)packet;
    short queryNum = ntohs(header->queryNum);
    short answerNum = ntohs(header->answerNum);
    for (int n = 0; n < queryNum; n++) {
        while (1) {
            if (packet[i] == '\0') {
                i++;
                break;
            }
            i += packet[i] + 1;
        }

        i += 4;
    }

    for (int n = 0; n < answerNum; n++) {
        if (packet[i] == 0xc0) {
            offset = packet[i + 1];
            i += 2;
        }
        // type
        memcpy(&rr->type, packet + i, sizeof(rr->type));
        i += sizeof(rr->type);
        // class
        memcpy(&rr->rclass, packet + i, sizeof(rr->rclass));
        i += sizeof(rr->rclass);
        // ttl
        memcpy(&rr->ttl, packet + i, sizeof(rr->ttl));
        i += sizeof(rr->ttl);
        // length
        memcpy(&rr->length, packet + i, sizeof(rr->length));
        i += sizeof(rr->length);
        if (ntohs(rr->type) == A) {
            struct in_addr *addr;
            memset(addr, 0, sizeof(struct in_addr));
            addr->s_addr = *(unsigned int *)(packet + i);
            // memcpy(&addr.sin_addr.s_addr,packet+i,4);

            rr->rdata = malloc(16);
            rr->rdata = inet_ntoa(*addr);
            free(addr);
        }
    }
}