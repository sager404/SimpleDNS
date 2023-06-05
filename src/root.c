#include "root.h"
#include "dns.h"
#include "server.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int deserialize_header(char *buffer, struct DNS_Header *header) {
    int offset = 0;

    header->id = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->flags = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->queryNum = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->answerNum = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->authorNum = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->addNum = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);

    return offset;
}

int deserialize_query(char *buffer, struct DNS_Query *query) {
    int offset = 0;

    unsigned char *rname = (unsigned char *)malloc(strlen(buffer) + 1);
    strcpy(rname, buffer);
    query->name = (unsigned char *)malloc(strlen(buffer) + 1);
    parse_name(rname, query->name);
    offset += strlen(buffer) + 1;
    query->qtype = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    query->qclass = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);

    return offset;
}

void gen_ns_rr(struct DNS_RR *rr, const unsigned char *name) {
    memset(rr, 0, sizeof(struct DNS_RR));
    unsigned char *rname = malloc((strlen(name) + 1) * sizeof(unsigned char));
    serialize_name(rname, name);
    rr->name = get_rname_domain(rname, 1);
    free(rname);
    rr->type = NS;
    rr->rclass = IN;
    rr->ttl = 86400;
}

void gen_a_rr() {}

int get_root_data(struct DNS_RR **RRs) {
    FILE *f = fopen("./data/root.txt", "r");

    *RRs = (struct DNS_RR *)malloc(ARRAY_CAPACITY * sizeof(struct DNS_RR));
    memset(*RRs, 0, ARRAY_CAPACITY * sizeof(struct DNS_RR));

    int cnt;
    for (cnt = 0; !feof(f); cnt++) {
        struct DNS_RR *rr = *RRs + cnt;
        char rclass[8] = {0};
        char type[8] = {0};
        rr->name =
            (unsigned char *)malloc(NAME_MAX_LENGTH * sizeof(unsigned char));
        rr->rdata =
            (unsigned char *)malloc(NAME_MAX_LENGTH * sizeof(unsigned char));

        memset(rr->name, 0, NAME_MAX_LENGTH);
        fscanf(f, "%s %d %s %s %s\n", rr->name, &rr->ttl, rclass, type,
               rr->rdata);
        rr->name = (unsigned char *)realloc(
            rr->name, (strlen(rr->name) + 1) * sizeof(unsigned char));
        rr->rdata = (unsigned char *)realloc(
            rr->rdata, (strlen(rr->rdata) + 1) * sizeof(unsigned char));
        rr->length = strlen(rr->rdata) + 2;

        if (!strcmp(rclass, "IN")) {
            rr->type = IN;
        } else
            exit(EXIT_FAILURE);

        if (!strcmp(type, "A")) {
            rr->type = A;
        } else if (!strcmp(type, "NS")) {
            rr->type = NS;
        } else
            exit(EXIT_FAILURE);

        if ((cnt + 1) % ARRAY_CAPACITY == 0) {
            *RRs = (struct DNS_RR *)realloc(*RRs,
                                       (cnt + ARRAY_CAPACITY) * sizeof(struct DNS_RR));
            memset(RRs + cnt + 1, 0, ARRAY_CAPACITY * sizeof(struct DNS_RR));
        }
    }
    fclose(f);
    return cnt;
}

unsigned short random_us() {
    srand(time(NULL));
    return (unsigned short)rand();
}

unsigned short gen_flags(unsigned char QR, unsigned char opcode,
                         unsigned char AA, unsigned char rcode) {
    if ((QR != 0 && QR != 1) || (AA != 0 && AA != 1))
        perror("Invalid input!");
    return ((unsigned short)QR << 15) + ((unsigned short)opcode << 11) +
           ((unsigned short)AA << 10) + (unsigned short)rcode;
}

void init_dns_header(struct DNS_Header *header, unsigned short id,
                     unsigned short flags, unsigned short q_num,
                     unsigned short ans_num, unsigned short auth_num,
                     unsigned short add_num) {
    header->id = htons(id);
    header->flags = htons(flags);
    header->queryNum = htons(q_num);
    header->answerNum = htons(ans_num);
    header->authorNum = htons(auth_num);
    header->addNum = htons(add_num);
}

void gen_response(char *buffer, struct DNS_Header *header,
                  struct DNS_Query *query) {
    memcpy(buffer, header, sizeof(struct DNS_Header));
    strcpy(buffer + sizeof(struct DNS_Header), query->name);
    memcpy(buffer + sizeof(struct DNS_Header) + strlen(query->name),
           query + sizeof(char *), sizeof(struct DNS_Query) - sizeof(char *));
}

int find_ns(struct DNS_RR *RRs, int cnt, struct DNS_Query *query) {
    for (int i = 0; i < cnt; i++) {
        if (RRs[i].type == NS && strstr(query->name, RRs[i].name))
            return i;
    }
    return -1;
}

int find_a_corresponding_ns(struct DNS_RR *RRs, int cnt,
                            const unsigned char *ns_rdata) {
    for (int i = 0; i < cnt; i++) {
        if (RRs[i].type == A && !strcmp(RRs[i].name, ns_rdata))
            return i;
    }
    return -1;
}