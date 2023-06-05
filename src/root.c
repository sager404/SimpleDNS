#include "root.h"
#include "dns.h"
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include "server.h"

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

int gen_ns_rr(struct DNS_RR *rr) {
    rr->name = get_root_name();
    rr->type = NS;
    rr->rclass = IN;
    rr->ttl = 86400;
}