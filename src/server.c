#include "server.h"
#include "dns.h"
#include "socket.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
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

void gen_udp_packet(char *packet, int len) {
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
    memcpy(&rr->type, packet + offset, sizeof(rr->type));
    offset += sizeof(rr->type);
    memcpy(&rr->rclass, packet + offset, sizeof(rr->rclass));
    offset += sizeof(rr->name);
    memcpy(&rr->ttl, packet + offset, sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(&rr->length, packet + offset, sizeof(rr->length));
    offset += sizeof(rr->length);
    int length = htons(rr->length);
    memcpy(rr->rdata, packet + offset, length);
    offset += length;
    return offset;
}

int get_local_cache(char *packet, struct DNS_Query *query, short offset) {
    FILE *fp = fopen("./data/local_server_cache.txt", "r");
    if (fp == NULL){
        perror("file open failed");
        return 0;
    }
    struct DNS_Header *header = (struct DNS_Header *)packet;
    short type = ntohs(query->qtype);
    char rname[128] = {0};
    if (ntohs(query->qtype) == PTR) {
        parse_ptr(query->name, rname);
    } else {
        parse_name(query->name, rname);
    }

    char rr_offset = sizeof(struct DNS_Header);
    while (!feof(fp)) {

        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        if (!strcmp(rname, name)) {
            int ntype = get_type(rtype);
            if (ntype == type || ntype == A) {
                struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
                if (ntype == A) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);

                    free(rr);
                    return 1;
                } else if (ntype == PTR) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);

                    free(rr);
                    return 1;
                } else {
                    header->addNum = htons(ntohs(header->addNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);
                    if (ntype == MX)
                        rr_offset += (14 + strlen(rdata) + 1);
                    else
                        rr_offset += (12 + strlen(rdata) + 1);
                    strcpy(rname, rdata);
                    // type = A;
                }

                free(rr);
            }
        }
    }
    fclose(fp);
    return 0;
}

void add_local_cache(char *packet, int ans_num) {

    FILE *fp = fopen("./data/local_server_cache.txt", "a");
    if (fp == NULL){
        perror("file open failed");
        return;
    }
    int offset = 0;
    for (int i = 0; i < ans_num; i++) {
        struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
        offset += parse_rr(packet + offset, rr);
        char name[128] = {0};
        char rdata[128] = {0};
        int ttl = ntohl(rr->ttl);
        char *rclass = "IN";
        char rtype[6] = {0};
        get_type_name(ntohs(rr->type), rtype);
        if (ntohs(rr->type) == PTR) {
            parse_ptr(rr->name, name);
            parse_name(rr->rdata, rdata);
        }

        else {
            parse_name(rr->name, name);
            if (ntohs(rr->type) == A)
                parse_addr(rdata, rr->rdata);
            else
                parse_name(rr->rdata, rdata);
        }
        fprintf(fp, "%s %d %s %s %s\n", name, ttl, rclass, rtype, rdata);
    }
    fclose(fp);
}