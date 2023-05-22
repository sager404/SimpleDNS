#include "dns.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>

void gen_dns_header(struct DNS_Header *header);
void gen_dns_query(struct DNS_Query *query,char* qname,short qtype);

int main(){
    int sock;
    struct sockaddr_in localserver_addr;
    int s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s<0)
        printf("socket failed");
    memset(&localserver_addr, 0, sizeof(localserver_addr));
    localserver_addr.sin_family = AF_INET;
    localserver_addr.sin_addr.s_addr = inet_addr("127.0.0.2");
    localserver_addr.sin_port = htons(UDP_PORT);

    struct DNS_Header *header=(struct DNS_Header *)malloc(sizeof(struct DNS_Header));
    struct DNS_Query *query=(struct DNS_Query *)malloc(sizeof(struct DNS_Query));
    gen_dns_header(header);
    char *qname="www.baidu.com";
    gen_dns_query(query, qname, 1);
    // memset(&header, 0, sizeof(header));
    // header.id=htons(1);

    // sendto(s, const void *buf, size_t n, 0, (struct sockaddr *) &localserver_addr, sizeof(localserver_addr));

}

void gen_dns_header(struct DNS_Header *header){

    header->id=htons(1);
    header->flags=0;
    header->queryNum=htons(1);
    header->answerNum=htons(0);
    header->authorNum=htons(0);
    header->addNum=htons(0);

}

void gen_dns_query(struct DNS_Query *query,char* qname,short qtype){

}