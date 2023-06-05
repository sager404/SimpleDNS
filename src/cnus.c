#include "cnus.h"

int get_cnus_data(struct DNS_RR **RRs) {
    FILE *f = fopen("./data/cnus.txt", "r");

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
            rr->rclass = IN;
        } else
            exit(EXIT_FAILURE);

        if (!strcmp(type, "A")) {
            rr->type = A;
        } else if (!strcmp(type, "NS")) {
            rr->type = NS;
        } else
            exit(EXIT_FAILURE);

        if ((cnt + 1) % ARRAY_CAPACITY == 0) {
            *RRs = (struct DNS_RR *)realloc(*RRs, (cnt + ARRAY_CAPACITY) *
                                                      sizeof(struct DNS_RR));
            memset(RRs + cnt + 1, 0, ARRAY_CAPACITY * sizeof(struct DNS_RR));
        }
    }
    fclose(f);
    return cnt;
}