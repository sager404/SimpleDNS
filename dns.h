#ifndef DNS_H_
#define DNS_H_

#define UDP_PORT 53
#define A 1
#define NS 2
#define CNAME 5
#define MX 15
#define PTR 12 

struct DNS_Header{
    unsigned short id;
    unsigned short flags;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
};

struct DNS_Query{
    unsigned char *name;
    unsigned short qtype;
    unsigned short qclass;
};

struct DNS_Response{
    unsigned char *name;
    unsigned short type;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short length;
    unsigned char *rdata;
};


#endif