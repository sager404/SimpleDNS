#include "dns.h"

void init_addr(struct sockaddr_in *sockaddr, const char *addr){
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
    int len = strlen(name) + 1;
    query->name = malloc(len + 1);
    memcpy(query->name + 1, name, len);
    int i = 0;
    int m = 0;
    char count = 0;
    while (1) {
        if (name[i] == '\0') {
            query->name[m] = count;
            break;
        }
        if (name[i] == '.') {
            query->name[m] = count;
            m += (count + 1);
            count = 0;
            i++;
        } else {
            i++;
            count++;
        }
    }
    query->qtype = htons(qtype);
    query->qclass = htons(IN);
}

void gen_dns_rr(struct DNS_RR *rr, short type, int ttl, char *addr,
                char offset) {
    rr->name[0] = 0xc0;
    rr->name[1] = offset;
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

int parse_query_packet(char *packet, struct DNS_Header *header,
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

void gen_dns_response(struct DNS_RR *answer, char *addr, char offset,
                      short type, int ttl) {
    answer->name[0] = 0xc0;
    answer->name[1] = offset;
    answer->type = htons(type);
    answer->rclass = htons(IN);
    answer->ttl = htonl(ttl);
    answer->rdata = addr;
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

void add_rr(char *packet, struct DNS_RR *rr, int offset) {
    memcpy(packet + offset, rr->name, sizeof(rr->name));
    offset += sizeof(rr->name);
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
}

int udp_socket() {
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("client: socket failed");
        close(sock);
    }
    return sock;
}
