#ifndef ROOT_H_
#define ROOT_H_

#include "dns.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LINE 10
#define DNS_MAX_LENGTH 1023

void initHead(struct DNS_Header *head);
void initQuery(struct DNS_Query *query);
void initRR(struct DNS_RR *rr);
int isequal(char *str1, char *str2);
void init_sockaddr_in(char *ip, int port, struct sockaddr_in *addr);
unsigned int getHeader(char *q, struct DNS_Header *header);
unsigned int getQuery(char *q, struct DNS_Query *query);
void splitOneDomainName(char *domainName, char *splitName);
unsigned int head2buf(char *o, struct DNS_Header *header);
unsigned int query2buf(char *o, struct DNS_Query *query);
unsigned int getRRs(char *q, struct DNS_RR *rRecord);
unsigned int rr2buf(char *o, struct DNS_RR *rr);

#endif