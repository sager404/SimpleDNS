#include "local_server.h"
#include "dns.h"


void init_local_addr(struct sockaddr_in *local_server_addr) {
    memset(local_server_addr, 0, sizeof(struct sockaddr_in));
    local_server_addr->sin_family = AF_INET;
    local_server_addr->sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    local_server_addr->sin_port = htons(DNS_PORT);
}

void gen_local_query_packet(char *packet, struct DNS_Header *header,
                            struct DNS_RR *rr, int len, char *rdata) {
    int offset = header->id;
    header->flags = FLAGS_RESPONSE;
    memcpy(packet + offset, &header->flags, sizeof(header->flags));
    offset = len;
    if (packet[offset] == NAME_PTR){
        memcpy(packet + offset, rr->name, 2);
        offset += 2;
    }else{

    }

    memcpy(packet + offset, &rr->type, sizeof(rr->type));
    offset += sizeof(rr->type);
    memcpy(packet + offset, &rr->rclass, sizeof(rr->rclass));
    offset += sizeof(rr->rclass);
    memcpy(packet + offset, &rr->ttl, sizeof(rr->ttl));
    offset += sizeof(rr->ttl);
    memcpy(packet + offset, &rr->length, sizeof(rr->length));
    offset += sizeof(rr->length);
    memcpy(packet + offset, rr->rdata, strlen(rdata));
    offset += strlen(rdata);
}

int get_local_cache(char *qname, short type, struct DNS_RR *rr) {
    FILE *fp = fopen("../data/local_server_cache.txt", "r");
    while (!feof(fp)) {
        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        if (!strcmp(qname, name)) {
            if (get_type(rtype) == A && type == A){
                gen_dns_rr(rr, A, ttl, rdata, 0x0c, name);
            }else if(get_type(rtype) == A && type == MX){
                gen_dns_rr(rr, MX, ttl, rdata, 0, name);
            }


            return 1;
        }
    }

    fclose(fp);
    return 0;
}
