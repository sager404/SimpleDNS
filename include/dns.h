#ifndef DNS_H_
#define DNS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define A 1
#define NS 2
#define CNAME 5
#define MX 15
#define PTR 12

#define IN 1
#define BUFSIZE 1024
#define DNS_PORT 53000
#define FLAGS_QUERY 0x0000
#define FLAGS_RESPONSE 0x8000

#define CLIENT_IP "127.0.0.1"
#define LOCAL_SERVER_IP "127.0.1.1"
#define ROOT_SERVER_IP "127.1.0.1"

struct DNS_Header {
    unsigned short id;
    unsigned short flags;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
};

struct DNS_Query {
    unsigned char *name;
    unsigned short qtype;
    unsigned short qclass;
};

struct DNS_RR {
    unsigned char name[2];
    unsigned short type;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short length;
    unsigned char *rdata;
};
void init_addr(struct sockaddr_in *sockaddr, const char *addr);
void serialize_addr(char *addr, char **rdata);
void gen_dns_header(struct DNS_Header *header, short flags, short qdcount,
                    short ancount);
void gen_dns_query(struct DNS_Query *query, char *name, short qtype);
void gen_dns_rr(struct DNS_RR *rr, short type, int ttl, char *addr,
                char offset);
int parse_query_packet(char *packet, struct DNS_Header *header,
                       struct DNS_Query *query, char *name);
void gen_response_packet(char *packet, struct DNS_Header *header,
                         short answerNum);
void gen_dns_response(struct DNS_RR *answer, char *addr, char offset,
                      short type, int ttl);
short get_type(char *type);
void add_rr(char *packet, struct DNS_RR *rr, int offset);
int udp_socket();

#endif