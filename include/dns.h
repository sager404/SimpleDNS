#ifndef DNS_H_
#define DNS_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define A 1
#define NS 2
#define CNAME 5
#define MX 15
#define PTR 12

#define IN 1
#define DNS_PORT 53
#define SENDER_PORT 54000
#define TRACER_PORT 54002
#define FLAGS_QUERY 0x0000
#define FLAGS_RESPONSE 0x8000
#define FLAGS_NOTFOUND 0x8003

#define NAME_PTR 0xc0
#define DOMAIN_MAX_LEVEL 16

#pragma pack(push, 1)

typedef struct DNS_Header {
    unsigned short id;
    unsigned short flags;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
} dns_header;

typedef struct DNS_Query {
    unsigned char *name;
    unsigned short qtype;
    unsigned short qclass;
} dns_query;

typedef struct DNS_RR {
    unsigned char *name;
    unsigned short type;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short length;
    unsigned char *rdata;
} dns_rr;

typedef struct Trace{
    unsigned int send_ip;
    unsigned short send_port;
    unsigned int recv_ip;
    unsigned short recv_port;
} trace;

#pragma pack(pop)

void init_addr(struct sockaddr_in *sockaddr, const char *addr);
void init_sender_addr(struct sockaddr_in *sockaddr, const char *addr);
void init_tracer_addr(struct sockaddr_in *sockaddr, const char *addr);
void parse_addr(char *addr, char *rdata);
void serialize_addr(char *addr, char **rdata);
void gen_dns_header(struct DNS_Header *header, short flags, short qdcount,
                    short ancount);
void gen_dns_query(struct DNS_Query *query, char *name, short qtype);
void gen_dns_rr(struct DNS_RR *rr, short type, int ttl, char *addr, char offset,
                char *name);
unsigned short parse_query_packet(char *packet, struct DNS_Header *header,
                                  struct DNS_Query *query);
void gen_response_packet(char *packet, struct DNS_Header *header,
                         short answerNum);
short get_type(char *type);
short get_type_name(short type, char *str);
short add_rr(char *packet, struct DNS_RR *rr);
void parse_name(char *rname, char *name);
void serialize_name(char *rname, char *name);
void serialize_ptr(char*data, char *ip);
void parse_ptr(char *data, char *ip);
short get_rname_length(unsigned char *rname);
unsigned char *get_rname_domain(const unsigned char *rname, int level);
uint16_t cal_packet_len(char *packet);
void free_rr(struct DNS_RR *rr);

#endif