#ifndef ORGCOM_H_
#define ORGCOM_H_
#include<stdio.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdint.h>
#include "dns.h"
#include "client.h"
#include "server.h"
#define LINE 10
#define DNS_MAX_LENGTH 1023


unsigned int getHeader(char *q, dns_header *header);
unsigned int getQuery(char *q, dns_query *query);
int isequal(char *str1, char* str2);
unsigned int rr2buf(char *o, dns_rr* rr);
unsigned int query2buf(char *o, dns_query *query);
unsigned int head2buf(char *o, dns_header *header);
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query);
int get_ORGCOM(char *packet, struct DNS_Query *query, short offset);

#endif