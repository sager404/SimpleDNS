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

int get_ORGCOM(char *packet, struct DNS_Query *query, short offset);
int deserialize_header(unsigned char *buffer, struct DNS_Header *header);
int deserialize_query(unsigned char *buffer, struct DNS_Query *query);

#endif