#include "edu.h"
#include "dns.h"

int get_EDU(char *packet, struct DNS_Query *query, short offset) {
    FILE *fp = fopen("./data/edu.txt", "r");
    if (fp == NULL){
        perror("file open failed");
        return 0;
    }
    struct DNS_Header *header = (struct DNS_Header *)packet;
    short type = ntohs(query->qtype);
    char rname[128] = {0};
    if (ntohs(query->qtype) == PTR) {
        parse_ptr(query->name, rname);
    } else {
        parse_name(query->name, rname);
    }

    char rr_offset = sizeof(struct DNS_Header);
    while (!feof(fp)) {

        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        if (!strcmp(rname, name)) {
            int ntype = get_type(rtype);
            if (ntype == type || ntype == A) {
                struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
                if (ntype == A) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);

                    free(rr);
                    return 1;
                } else if (ntype == PTR) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);

                    free(rr);
                    return 1;
                } else {
                    header->addNum = htons(ntohs(header->addNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);
                    if (ntype == MX)
                        rr_offset += (14 + strlen(rdata) + 1);
                    else
                        rr_offset += (12 + strlen(rdata) + 1);
                    strcpy(rname, rdata);
                    // type = A;
                }

                free(rr);
            }
        }
    }
    fclose(fp);
    return 0;
}