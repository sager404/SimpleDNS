#include "dns.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void init_addr(struct sockaddr_in *sockaddr, const char *addr) {
    memset(sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = inet_addr(addr);
    sockaddr->sin_port = htons(DNS_PORT);
}

void init_sender_addr(struct sockaddr_in *sockaddr, const char *addr) {
    memset(sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = inet_addr(addr);
    sockaddr->sin_port = htons(SENDER_PORT);
}

void serialize_addr(char *addr, char **rdata) {
    in_addr_t in_addr = inet_addr(addr);
    // unsigned char *ptr = &in_addr;
    // for (int i = 0; i < 4; i++)
    //     rdata[i] = ptr[i];
    *rdata = (unsigned int *)&in_addr;
}

void parse_addr(char *addr, char *rdata) {
    struct in_addr a;
    memset(&a, 0, sizeof(struct in_addr));
    a.s_addr = *(unsigned int *)(rdata);
    char *tmp = inet_ntoa(a);
    memcpy(addr, tmp, strlen(tmp));
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
    int len;

    if (qtype == PTR) {
        len = strlen(name) + 15;
        query->name = malloc(len);
        serialize_ptr(query->name, name);

    } else {
        len = strlen(name) + 1;
        query->name = malloc(len + 1);
        serialize_name(query->name, name);
    }

    query->qtype = htons(qtype);
    query->qclass = htons(IN);
}

void gen_dns_rr(struct DNS_RR *rr, short type, int ttl, char *addr, char offset,
                char *name) {
    if (offset != 0) {
        rr->name = malloc(2);
        rr->name[0] = NAME_PTR;
        rr->name[1] = offset;
    } else {
        rr->name = malloc(strlen(name) + 2);
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
    } else if (type == MX) {
        len = strlen(addr) + 4;
        rr->rdata = malloc(len);

        serialize_name(rr->rdata + 2, addr);
    } else {
        len = strlen(addr) + 2;
        rr->rdata = malloc(len);
        serialize_name(rr->rdata, addr);
    }

    rr->length = htons(len);
}

unsigned short parse_query_packet(char *packet, struct DNS_Header *header,
                                  struct DNS_Query *query) {

    unsigned short offset = sizeof(struct DNS_Header);
    char name[128] = {0};
    for (int n = 0; n < ntohs(header->queryNum); n++) {
        int len = 0;
        int start = offset;
        do {
            offset++;
            len++;
        } while (packet[offset] != '\0');
        query->name = malloc(++len);
        memcpy(query->name, packet + start, len);
        offset++;

    }

    memcpy(&query->qtype, packet + offset, sizeof(query->qtype));
    offset += sizeof(query->qtype);
    memcpy(&query->qclass, packet + offset, sizeof(query->qclass));
    offset += sizeof(query->qclass);

    return offset;
}

void gen_response_packet(char *packet, struct DNS_Header *header,
                         short answerNum) {
    header->flags = htons(FLAGS_RESPONSE);
    header->answerNum = htons(answerNum);
    memcpy(packet, header, sizeof(struct DNS_Header));
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

short get_type_name(short type, char *str) {
    if (type == A)
        strcpy(str, "A");
    else if (type == CNAME)
        strcpy(str, "CNAME");
    else if (type == MX)
        strcpy(str, "MX");
    else if (type == PTR)
        strcpy(str, "PTR");
}

short add_rr(char *packet, struct DNS_RR *rr) {
    int offset = 0;
    if (rr->name[0] == NAME_PTR) {
        memcpy(packet + offset, rr->name, 2);
        offset += 2;
    } else {
        int len = get_rname_length(rr->name);
        memcpy(packet + offset, rr->name, len);
        offset += len;
    }

    memcpy(packet + offset, &rr->type, sizeof(rr->type));
    offset += sizeof(rr->type);
    memcpy(packet + offset, &rr->rclass, sizeof(rr->rclass));
    offset += sizeof(rr->rclass);
    memcpy(packet + offset, &rr->ttl, sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(packet + offset, &rr->length, sizeof(rr->length));
    offset += sizeof(rr->length);
    int length = htons(rr->length);
    memcpy(packet + offset, rr->rdata, length);
    offset += length;
    return offset;
}

short get_name_offset(char *packet, char *name) {
    short offset = sizeof(struct DNS_Header);
}

void parse_name(char *rname, char *name) {
    int i = 0;
    while (rname[i] != '\0') {
        memcpy(name + i, rname + i + 1, rname[i]);
        i += (rname[i] + 1);
        name[i - 1] = '.';
    }
    name[i - 1] = '\0';
}

void serialize_name(char *rname, char *name) {
    int len = strlen(name) + 1;
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
    rname[m] = --count;
}

void serialize_ptr(char *data, char *ip) {
    char tmp[128] = {0};
    strcpy(tmp, ip);
    int len = strlen(ip);

    for (int i = 0; i < len; i++) {
        tmp[i] = ip[len - i - 1];
    }
    strcat(tmp, ".in-addr.arpa");
    serialize_name(data, tmp);
}

void parse_ptr(char *data, char *ip) {
    int i = 0;
    char tmp[128];
    for (int j = 0; j < 4; j++) {
        memcpy(tmp + i, data + i + 1, data[i]);
        i += (data[i] + 1);
        tmp[i - 1] = '.';
    }
    tmp[i - 1] = '\0';
    int len = strlen(tmp);
    for (int j = 0; j < len; j++) {
        ip[j] = tmp[len - j - 1];
    }
}

short get_rname_length(unsigned char *rname) {
    if (rname[0] == NAME_PTR)
        return 2;
    int i = 0;
    while (rname[i] != 0x00) {
        i += (rname[i] + 1);
    }
    return ++i;
}

unsigned char *get_rname_domain(const unsigned char *rname, int level) {
    unsigned char *tmp =
        (unsigned char *)malloc(strlen(rname) * sizeof(unsigned char));
    strcpy(tmp, rname);

    int lengths[DOMAIN_MAX_LEVEL] = {0};
    unsigned char *domains[DOMAIN_MAX_LEVEL] = {NULL};
    int l = 0;

    for (int i = 0; tmp[i] != '\0'; i += tmp[i] + 1) {
        lengths[l] = tmp[i] + 1;
        domains[l] = tmp + i;
        l++;
    }

    unsigned char *domain =
        (unsigned char *)malloc((lengths[l - level] + 1) * sizeof(unsigned char));
    memset(domain, 0, lengths[l - level] + 1);
    memcpy(domain, domains[l - level], lengths[l - level] + 1);
    free(tmp);
    return domain;
}

uint16_t cal_packet_len(char *packet) {
    struct DNS_Header *header = (struct DNS_Header *)(packet);
    uint16_t len = sizeof(*header);
    for (int i = 0; i < ntohs(header->queryNum); i++) {
        len += get_rname_length(packet + len);
        len += 4;
    }
    int num = ntohs(header->answerNum) + ntohs(header->addNum) +
              ntohs(header->authorNum);
    for (int i = 0; i < num; i++) {
        len += get_rname_length(packet + len);
        // type rclass ttl
        len += 8;
        len += ntohs(*(short *)(packet + len));
        len += 2;
    }

    return len;
}

void free_rr(struct DNS_RR *rr) {
    free(rr->name);
    free(rr->rdata);
    free(rr);
}