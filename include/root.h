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
#define DNS_MAX_LENGTH 1024

int deserialize_header(char *buffer, struct DNS_Header *header);
int deserialize_query(char *buffer, struct DNS_Query *query);

#endif