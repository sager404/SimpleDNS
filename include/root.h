#ifndef ROOT_H_
#define ROOT_H_
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
#define LINE 10
#define DNS_MAX_LENGTH 1023

void initHead(dns_header *head);
void initQuery(dns_query *query);
void initRR(dns_rr *rr);
int isequal(char *str1, char* str2);
void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr);
unsigned int getHeader(char *q, dns_header *header);
unsigned int getQuery(char *q, dns_query *query);
void splitOneDomainName(char *domainName, char *splitName);
unsigned int head2buf(char *o, dns_header *header);
unsigned int query2buf(char *o, dns_query *query);
unsigned int getRRs(char *q, dns_rr *rRecord);
unsigned int rr2buf(char *o, dns_rr* rr); 

#endif