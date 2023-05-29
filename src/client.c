#include "client.h"


void init_client_addr(struct sockaddr_in *local_server_addr) {
    memset(local_server_addr, 0, sizeof(struct sockaddr_in));
    local_server_addr->sin_family = AF_INET;
    local_server_addr->sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    local_server_addr->sin_port = htons(DNS_PORT);
}

void gen_client_query_packet(char *packet, struct DNS_Header *header,
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
