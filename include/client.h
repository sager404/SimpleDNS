#ifndef CLIENT_H_
#define CLIENT_H_

#include "dns.h"

#define CLIENT_IP "127.0.0.1"

int gen_client_query_packet(char *packet, struct DNS_Header *header,
                            struct DNS_Query *query);
void parse_dns_response(unsigned char *packet, struct DNS_RR *rr);

#endif