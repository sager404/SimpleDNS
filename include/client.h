#ifndef CLIENT_H_
#define CLIENT_H_

#include "dns.h"

void init_client_addr(struct sockaddr_in *local_server_addr);
void gen_client_query_packet(char *packet, struct DNS_Header *header,
                             struct DNS_Query *query, char *qname);
void parse_dns_response(unsigned char *packet, struct DNS_RR *rr);

#endif