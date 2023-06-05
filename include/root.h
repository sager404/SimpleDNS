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
#define NAME_MAX_LENGTH 128
#define ARRAY_CAPACITY 20

#define OP_STD 0
#define OP_INV 1

#define R_FINE 0
#define R_NAME_ERROR 3
#define R_TYPE_ERROR 4

int deserialize_header(char *buffer, struct DNS_Header *header);
int deserialize_query(char *buffer, struct DNS_Query *query);
void gen_ns_rr(struct DNS_RR *rr, const unsigned char *name);
int get_root_data(struct DNS_RR *RRs);
unsigned short random_us();
unsigned short gen_flags(unsigned char QR, unsigned char opcode,
                         unsigned char AA, unsigned char rcode);
void init_dns_header(struct DNS_Header *header, unsigned short id,
                     unsigned short flags, unsigned short q_num,
                     unsigned short ans_num, unsigned short auth_num,
                     unsigned short add_num);
void gen_response(char *buffer, struct DNS_Header *header,
                  struct DNS_Query *query);
int find_ns(struct DNS_RR *RRs, int cnt, struct DNS_Query *query);
int find_a_corresponding_ns(struct DNS_RR *RRs, int cnt, const unsigned char *ns_rdata);

#endif