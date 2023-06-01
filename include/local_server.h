#ifndef LOCAL_SERVER_H_
#define LOCAL_SERVER_H_

#include "dns.h"

void init_local_addr(struct sockaddr_in *local_server_addr);
void gen_local_query_packet(char *packet, struct DNS_Header *header,
                            struct DNS_RR *rr, int len, char *rdata);
int get_local_cache(char *qname, short type, struct DNS_RR *rr);

#endif