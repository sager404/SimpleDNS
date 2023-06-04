#include "root.h"
#include "dns.h"

int gen_root_query_packet(char *packet, struct DNS_Header *header,
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