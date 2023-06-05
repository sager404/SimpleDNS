#include "client.h"
#include "dns.h"
#include <netinet/in.h>
#include <stdlib.h>

int gen_client_query_packet(char *packet, struct DNS_Header *header,
                            struct DNS_Query *query) {
    memcpy(packet, header, sizeof(struct DNS_Header));
    int name_len = get_rname_length(query->name);
    int offset = sizeof(struct DNS_Header);
    memcpy(packet + offset, query->name, name_len);
    offset += name_len;
    memcpy(packet + offset, &query->qtype, sizeof(query->qtype));
    offset += sizeof(query->qtype);
    memcpy(packet + offset, &query->qclass, sizeof(query->qclass));
    offset += sizeof(query->qclass);
    return offset;
}

void parse_dns_response(unsigned char *packet, struct DNS_RR *rr) {
    int i = 0, j = 0;
    int name_len = 0;
    int offset = 0;

    i += sizeof(struct DNS_Header);
    struct DNS_Header *header = (struct DNS_Header *)packet;
    short queryNum = ntohs(header->queryNum);
    short num = ntohs(header->answerNum) + ntohs(header->addNum);
    for (int n = 0; n < queryNum; n++) {
        i += get_rname_length(packet + i);

        i += 4;
    }

    for (int n = 0; n < num; n++) {

        i += get_rname_length(packet + i);

        // type
        memcpy(&rr->type, packet + i, sizeof(rr->type));
        rr->type = ntohs(rr->type);
        i += sizeof(rr->type);
        // class
        memcpy(&rr->rclass, packet + i, sizeof(rr->rclass));
        rr->rclass = ntohs(rr->rclass);
        i += sizeof(rr->rclass);
        // ttl
        memcpy(&rr->ttl, packet + i, sizeof(rr->ttl));
        rr->ttl = ntohl(rr->ttl);
        i += sizeof(rr->ttl);
        // length
        memcpy(&rr->length, packet + i, sizeof(rr->length));
        rr->length = ntohs(rr->length);
        i += sizeof(rr->length);

        if (rr->type == A) {
            rr->rdata = malloc(16);
            parse_addr(rr->rdata, packet + i);
        }else if (rr->type == PTR){
            int len = get_rname_length(packet+i);
            rr->rdata = malloc(len-1);
            parse_name(packet+i, rr->rdata);
        }
        i += rr->length;
    }
}
