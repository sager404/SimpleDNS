#include "server.h"
#include "dns.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

void gen_tcp_packet(char *packet, int len) {
    char tmp[BUFSIZE] = {0};
    unsigned int nlen = htons(len);
    memcpy(tmp, packet, len);
    memcpy(packet, &nlen, 2);
    memcpy(packet + 2, tmp, len);
}

void gen_udp_packet(char *packet, int len){
    char tmp[BUFSIZE] = {0};
    memcpy(tmp, packet, len);
    memcpy(packet + 2, tmp, len);
}

void update_packet_len(char *packet) {
    u_int16_t len = cal_packet_len(packet + 2);
    memcpy(packet, &len, 2);
}

void get_root_name(char *name, char *root) {

    int i = 0;
    char tmp[16];
    while (name[i] != '\0') {
        memset(tmp, 0, 16);
        memcpy(tmp, name + i + 1, name[i]);
        i += (name[i] + 1);
    }
    strcpy(root, tmp);
}

void get_second_name(char *rname, char *name) {
    int i = 0;
    int idx[10] = {0};
    int count = 0;
    while (name[i] != '\0') {
        idx[count] = i;
        i += (name[i] + 1);
        count++;
    }
    int start = idx[count - 2];
    memcpy(name, rname + start + 1, rname[start]);
}

void get_third_name(char *rname, char *name) {
    int i = 0;
    int idx[10] = {0};
    int count = 0;
    while (name[i] != '\0') {
        idx[count] = i;
        i += (name[i] + 1);
        count++;
    }
    int start = idx[count - 3];
    memcpy(name, rname + start + 1, rname[start]);
}

int parse_rr(char *packet, struct DNS_RR *rr) {
    int len = get_rname_length(packet);
    rr->name = malloc(len);
    memcpy(rr->name, packet, len);
    int offset = len;
    memcpy(&rr->type,packet + offset,  sizeof(rr->type));
    offset += sizeof(rr->type);
    memcpy(&rr->rclass,packet + offset,  sizeof(rr->rclass));
    offset += sizeof(rr->name);
    memcpy(&rr->ttl,packet + offset,  sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(&rr->length,packet + offset,  sizeof(rr->length));
    offset += sizeof(rr->length);
    int length = htons(rr->length);
    memcpy(rr->rdata, packet + offset, length);
    offset += length;
    return offset;
}

int get_local_cache(struct DNS_Query *query, struct DNS_RR *rr) {
    FILE *fp = fopen("./data/local_server_cache.txt", "r");

    short type = ntohs(query->qtype);
    while (!feof(fp)) {
        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        char rname[128] = {0};
        parse_name(query->name,rname);
        if (!strcmp(rname, name)) {
            if (get_type(rtype) == type) {
                gen_dns_rr(rr, type, ttl, rdata, 0x0c, name);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

int udp_socket() {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("client: socket failed");
        close(sock);
    }
    return sock;
}

int tcp_socket() {
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("client: socket failed");
        close(sock);
    }
    return sock;
}

void tcp_connect(int sock, struct sockaddr_in *dest_addr) {
    if (connect(sock, (struct sockaddr *)dest_addr,
                sizeof(struct sockaddr_in)) == -1) {
        perror("client: failed to connect to server");
        exit(EXIT_FAILURE);
    }
}

void tcp_listen(int sock) {
    if (listen(sock, LISTEN_BACKLOG) == -1) {
        perror("server: failed to listen");
        exit(EXIT_FAILURE);
    }
}

int tcp_accept(int sock, struct sockaddr_in *client_addr) {
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    int client_sock =
        accept(sock, (struct sockaddr *)client_addr, &client_addr_len);
    if (client_sock == -1) {
        perror("Failed to accept");
        exit(EXIT_FAILURE);
    }
    return client_sock;
}

void tcp_send(int sock, char *buffer) {
    if (send(sock, buffer, strlen(buffer), 0) != strlen(buffer)) {
        perror("client: send failed");
    }
}

ssize_t tcp_receive(int sock, char *buffer) {
    ssize_t rlen = recv(sock, buffer, BUFSIZE - 1, 0);
    if (rlen == -1) {
        perror("server: receive failed");
        exit(EXIT_FAILURE);
    } else if (rlen == 0) {
        printf("server: client disconnected\n");
    }
    return rlen;
}