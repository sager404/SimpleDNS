#ifndef GOV_H_
#define GOV_H_
#include "dns.h"
#include "server.h"
#include "socket.h"

#define LINE 10
#define DNS_MAX_LENGTH 1023

int get_GOV(char *packet, struct DNS_Query *query, short offset);
int deserialize_header(unsigned char *buffer, struct DNS_Header *header);
int deserialize_query(unsigned char *buffer, struct DNS_Query *query);

#endif