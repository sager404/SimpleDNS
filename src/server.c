#include "server.h"
#include "dns.h"
#include "socket.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
    memcpy(tmp, packet + 2, len);
    memset(packet, 0, len + 2);
    memcpy(packet, tmp, len);
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
    offset += sizeof(rr->rclass);
    memcpy(&rr->ttl, packet + offset, sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(&rr->length, packet + offset, sizeof(rr->length));
    offset += sizeof(rr->length);
    unsigned short length = ntohs(rr->length);
    if (ntohs(rr->type) == MX) {
        rr->rdata = malloc(length);
        memcpy(rr->rdata, packet + offset + 2, length - 2);

    } else {
        rr->rdata = malloc(length);
        memcpy(rr->rdata, packet + offset, length);
    }

    offset += length;
    return offset;
}

int parse_packet_rr(char *packet, struct DNS_RR *rr, int offset) {
    char name[128] = {0};

    int len = get_rname_length(packet + offset);
    if (len == 2) {
        char tmp[128] = {0};
        char j = packet[offset + 1];
        rr->name = malloc(strlen(packet + j));
        strcpy(rr->name, packet + j);
        offset += 2;

    } else {
        rr->name = malloc(len);
        memcpy(rr->name, packet, len);
        offset += len;
    }

    memcpy(&rr->type, packet + offset, sizeof(rr->type));
    offset += sizeof(rr->type);
    memcpy(&rr->rclass, packet + offset, sizeof(rr->rclass));
    offset += sizeof(rr->rclass);
    memcpy(&rr->ttl, packet + offset, sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(&rr->length, packet + offset, sizeof(rr->length));
    offset += sizeof(rr->length);
    unsigned short length = ntohs(rr->length);
    rr->rdata = malloc(length);
    memcpy(rr->rdata, packet + offset, length);
    offset += length;
    return offset;
}

int load_data(char *packet, struct DNS_Query *query, short *offset,
              const char *file) {
    char file_name[32] = "./data/";
    strcat(file_name, file);
    FILE *fp = fopen(file_name, "r");
    if (fp == NULL) {
        perror("file open failed");
        return 0;
    }
    int ret = 0;
    int flag = 0;
    struct DNS_Header *header = (struct DNS_Header *)(packet + *offset - 12);
    short type = ntohs(query->qtype);
    char rname[128] = {0};
    if (ntohs(query->qtype) == PTR) {
        parse_ptr(query->name, rname);
    } else {
        parse_name(query->name, rname);
    }

    char rr_offset = *offset;
    *offset += get_rname_length(packet + *offset);
    *offset += 4;
    while (!feof(fp)) {

        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        if (!strcmp(rname, name)) {
            int ntype = get_type(rtype);
            if (ntype == type) {
                struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));

                gen_dns_rr(rr, ntype, ttl, rdata, 0, name);
                *offset += add_rr(packet + *offset, rr);
                if (ntype == PTR) {
                    header->addNum = htons(ntohs(header->addNum) + 1);
                    free(rr);
                    return 1;
                } else if (ntype == MX) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    flag = 1;
                    rr_offset += (14 + strlen(rdata) + 1);
                    bzero(rname, 128);
                    strcpy(rname, rdata);
                    type = A;

                } else if (ntype == NS) {
                    header->authorNum = htons(ntohs(header->authorNum) + 1);
                    flag = 1;
                    rr_offset += (12 + strlen(rdata) + 1);
                    bzero(rname, 128);
                    strcpy(rname, rdata);
                } else {
                    if (flag) {
                        header->addNum = htons(ntohs(header->addNum) + 1);
                    } else {
                        header->answerNum = htons(ntohs(header->answerNum) + 1);
                    }
                    rr_offset += (12 + strlen(rdata) + 1);
                    ret = 1;
                }

                free(rr);
            }
        }
    }
    fclose(fp);
    return ret;
}

void add_local_cache(char *packet, int query_len) {

    FILE *fp = fopen("./data/local_server_cache.txt", "a");
    if (fp == NULL) {
        perror("file open failed");
        return;
    }
    int offset = query_len;
    struct DNS_Header *header = (struct DNS_Header *)packet;
    int ans_num = ntohs(header->answerNum) + ntohs(header->addNum);
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
        free_rr(rr);
    }
    fclose(fp);
}

void gen_trace_packet(char *packet, const char *send, const char *recv,
                      int flag) {
    unsigned short f = htons(0xff00);
    memcpy(packet, &f, 2);
    char tmp[64] = {0};
    char ip[6] = {0};
    if (flag) {
        unsigned short p = htons(SENDER_PORT);
        char port[3] = {0};
        serialize_addr(send, &ip);
        strcat(tmp, send);
        memcpy(packet + 2, ip, 4);
        memcpy(packet + 6, &p, 2);
        serialize_addr(recv, &ip);
        memcpy(packet + 8, ip, 4);
        p = htons(DNS_PORT);
        memcpy(packet + 10, p, 2);
    } else {
        unsigned short p = htons(SENDER_PORT);
        char port[3] = {0};
        serialize_addr(send, &ip);
        memcpy(packet + 2, ip, 4);
        memcpy(packet + 6, &p, 2);
        serialize_addr(recv, &ip);
        memcpy(packet + 8, ip, 4);
        p = htons(DNS_PORT);
        memcpy(packet + 10, p, 2);
    }
}

void print_trace(struct Trace *trace) {
    FILE *fp = fopen("./data/trace.txt", "a");
    char *send_ip = malloc(32);

    struct in_addr s = {0};
    s.s_addr = trace->send_ip;

    char *tmp = inet_ntoa(s);
    memcpy(send_ip, tmp, strlen(tmp));
    char *recv_ip = malloc(32);
    struct in_addr r = {0};
    r.s_addr = trace->recv_ip;
    tmp = inet_ntoa(r);
    memcpy(recv_ip, tmp, strlen(tmp));
    fprintf(fp, "%s:%d -> %s:%d\n", send_ip, ntohs(trace->send_port), recv_ip,
            ntohs(trace->recv_port));

    free(send_ip);
    free(recv_ip);
    fclose(fp);
}
