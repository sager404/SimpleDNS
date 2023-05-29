#include "dns.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct sockaddr_in rootserver_addr;
struct sockaddr_in client_addr;
struct sockaddr_in localserver_addr;
int sock_in;

int get_cache(char *qname, char *data, struct DNS_RR *rr);
void add_rr(char *packet, struct DNS_RR *rr, int offset);

void init_localserver() {
    sock_in = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_in < 0) {
        perror("local-server: socket failed");
        close(sock_in);
    }

    memset(&localserver_addr, 0, sizeof(localserver_addr));
    localserver_addr.sin_family = AF_INET;
    localserver_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    localserver_addr.sin_port = htons(DNS_PORT);
    memset(&rootserver_addr, 0, sizeof(rootserver_addr));
    rootserver_addr.sin_family = AF_INET;
    rootserver_addr.sin_addr.s_addr = inet_addr(ROOT_SERVER_IP);
    rootserver_addr.sin_port = htons(DNS_PORT);
}

int main() {
    init_localserver();
    char name[127] = {0};
    char packet[BUFSIZE] = {0};
    // char packet_res[1023] = {0};
    unsigned int client_addr_len = sizeof(client_addr);
    if (bind(sock_in, (struct sockaddr *)&localserver_addr,
             sizeof(localserver_addr)) < 0) {
        perror("local-server: bind failed");
    }
    int packet_len;
    packet_len = recvfrom(sock_in, packet, sizeof(packet), 0,
                          (struct sockaddr *)&client_addr, &client_addr_len);
    if (packet_len < 0) {
        perror("Revieve from client failed");
    }
    struct DNS_Header *header = (struct DNS_Header *)packet;
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));
    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
    // strcpy(packet_res, packet_query);

    int offset = parse_query_packet(packet, header, query, name);
    char data[127] = {0};
    if (get_cache(name, data, rr)) {
        printf("%s", query->name);
        add_rr(packet, rr, offset + 1);
        gen_response_packet(packet, header, 1);
        sendto(sock_in, packet, sizeof(packet), 0,
               (struct sockaddr *)&client_addr, sizeof(client_addr));
        free(query);
        free(rr);
    }
}

void gen_query_packet(char *packet, struct DNS_Header *header,
                      struct DNS_RR *rr, int len, char *rdata) {
    int offset = header->id;
    header->flags = FLAGS_RESPONSE;
    memcpy(packet + offset, &header->flags, sizeof(header->flags));
    offset = len;
    memcpy(packet + offset, rr->name, sizeof(rr->name));
    offset += sizeof(rr->name);
    memcpy(packet + offset, &rr->type, sizeof(rr->type));
    offset += sizeof(rr->type);
    memcpy(packet + offset, &rr->rclass, sizeof(rr->rclass));
    offset += sizeof(rr->rclass);
    memcpy(packet + offset, &rr->ttl, sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(packet + offset, &rr->length, sizeof(rr->length));
    offset += sizeof(rr->length);
    memcpy(packet + offset, rr->rdata, strlen(rdata));
    offset += strlen(rdata);
}

int get_cache(char *qname, char *data, struct DNS_RR *rr) {
    FILE *fp = fopen("./data/local_server_cache.txt", "r");
    while (!feof(fp)) {
        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char type[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, type, rdata);
        if (!strcmp(qname, name)) {

            gen_dns_rr(rr, get_type(type), ttl, rdata, 0x0c);
            data = rdata;
            return 1;
        }
    }

    fclose(fp);
    return 0;
}
