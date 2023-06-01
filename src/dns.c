#include "dns.h"
#include <stdint.h>
#include <string.h>

void init_addr(struct sockaddr_in *sockaddr, const char *addr) {
    memset(sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = inet_addr(addr);
    sockaddr->sin_port = htons(DNS_PORT);
}

void serialize_addr(char *addr, char **rdata) {
    in_addr_t in_addr = inet_addr(addr);
    // unsigned char *ptr = &in_addr;
    // for (int i = 0; i < 4; i++)
    //     rdata[i] = ptr[i];
    *rdata = (unsigned int *)&in_addr;
}

void gen_dns_header(struct DNS_Header *header, short flags, short qdcount,
                    short ancount) {
    header->id = htons(1);
    header->flags = htons(flags);
    header->queryNum = htons(qdcount);
    header->answerNum = htons(ancount);
    header->authorNum = 0;
    header->addNum = 0;
}

void gen_dns_query(struct DNS_Query *query, char *name, short qtype) {
    serialize_name(query->name, name);

    query->qtype = htons(qtype);
    query->qclass = htons(IN);
}

void gen_dns_rr(struct DNS_RR *rr, short type, int ttl, char *addr, char offset,
                char *name) {
    if (offset == 0) {
        memset(rr->name, 0, 2);
        rr->name[0] = NAME_PTR;
        rr->name[1] = offset;
    } else {
        serialize_name(rr->name, name);
    }

    rr->rclass = htons(IN);
    rr->type = htons(type);
    rr->ttl = htonl(ttl);

    unsigned short len = 0;
    if (type == A) {
        len = 4;
        rr->rdata = malloc(len);
        serialize_addr(addr, &rr->rdata);
    } else {
        len = strlen(addr) + 1;
        rr->rdata = malloc(len);
        strcpy(rr->rdata, addr);
    }

    rr->length = htons(len);
}

short parse_query_packet(char *packet, struct DNS_Header *header,
                         struct DNS_Query *query, char *name) {
    int i = 0;
    int j = 0;
    int name_len = 0;
    int offset = 0;

    offset = sizeof(struct DNS_Header);
    i += offset;
    for (int n = 0; n < ntohs(header->queryNum); n++) {
        while (1) {
            if (packet[i] == '\0') {
                j--;
                name[j] = '\0';
                name_len = j;
                query->name = malloc(name_len);
                memcpy(query->name, name, name_len);
                break;
            }
            memcpy(name + j, packet + i + 1, packet[i]);

            j += packet[i];
            i += packet[i] + 1;
            name[j] = '.';
            j++;
        }
    }

    memcpy(&query->qtype, packet + i, sizeof(query->qtype));
    i += sizeof(header->addNum);
    memcpy(&query->qclass, packet + i, sizeof(query->qclass));
    i += sizeof(query->qclass);

    return i;
}

void gen_response_packet(char *packet, struct DNS_Header *header,
                         short answerNum) {
    header->flags = htons(FLAGS_RESPONSE);
    header->answerNum = htons(answerNum);
    // memcpy(packet,header,sizeof(struct DNS_Header));
}

short get_type(char *type) {
    if (!strcmp("A", type))
        return A;
    else if (!strcmp("NS", type))
        return NS;
    else if (!strcmp("CNAME", type))
        return CNAME;
    else if (!strcmp("MX", type))
        return MX;
    else if (!strcmp("PTR", type))
        return PTR;
    else
        return 0;
}

short add_rr(char *packet, struct DNS_RR *rr, int offset) {
    if (rr->name[0] == NAME_PTR) {
        memcpy(packet + offset, rr->name, 2);
        offset += 2;
    } else {
        int len = get_name_length(rr->name);
        memcpy(packet + offset, rr->name, len);
        offset += len;
    }

    memcpy(packet + offset, &rr->type, sizeof(rr->type));
    offset += sizeof(rr->type);
    memcpy(packet + offset, &rr->rclass, sizeof(rr->rclass));
    offset += sizeof(rr->name);
    memcpy(packet + offset, &rr->ttl, sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(packet + offset, &rr->length, sizeof(rr->length));
    offset += sizeof(rr->name);
    int length = htons(rr->length);
    memcpy(packet + offset, rr->rdata, length);
    offset += length;
    return offset;
}

short get_name_offset(char *packet, char *name) {
    short offset = sizeof(struct DNS_Header);
}

void parse_name(char *rname, char *name) {}

void serialize_name(char *rname, char *name) {
    int len = strlen(name) + 1;
    rname = malloc(len + 1);
    memcpy(rname + 1, name, len);
    int m = 0;
    char count = 0;
    for (int i = 0; i < len; i++) {
        if (name[i] == '.') {
            rname[m] = count;
            m += (count + 1);
            count = 0;
        } else {
            count++;
        }
    }
    rname[m] = count;
}

short get_name_length(unsigned char *rname) {
    if (rname[0] == NAME_PTR)
        return 2;
    int i = 0;
    int len = 0;
    while (rname[i] != 0x00) {
        i += (rname[i] + 1);
    }
    return i++;
}

uint16_t cal_packet_len(char *packet) {
    struct DNS_Header *header = (struct DNS_Header *)(packet + 2);
    uint16_t len = sizeof(*header);
    for (int i = 0; i < header->queryNum; i++) {
        len += get_name_length(packet + len);
        len += 4;
    }
    for (int i = 0; i < header->answerNum; i++) {
        len += get_name_length(packet + len);
        // type rclass ttl
        len += 8;
        len += *(short *)(packet + len);
        len += 2;
    }
    return len;
}
