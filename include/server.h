#ifndef SERVER_H_
#define SERVER_H_

#include "dns.h"

#define LOCAL_SERVER_IP "127.0.0.2"
#define ROOT_SERVER_IP "127.0.1.1"
#define TLD1_SERVER_IP "127.1.1.1"
#define TLD2_SERVER_IP "127.1.1.2"
#define SCD1_SERVER_IP "127.1.2.1"
#define SCD2_SERVER_IP "127.1.2.2"
#define TLD1_SERVER_NAME "ns.com"

void gen_tcp_packet(char *packet, int len);
void update_packet_len(char *packet);
void get_root_name(char *name, char *root);
void get_second_name(char *rname, char *name);
void get_third_name(char *rname, char *name);
int parse_rr(char *packet, struct DNS_RR *rr);
int parse_packet_rr(char *packet, struct DNS_RR *rr, int offset);
void add_local_cache(char *packet, int ans_num);
int load_data(char *packet, struct DNS_Query *query, short *offset,
              const char *file);
void gen_udp_packet(char *packet, int len);
void print_trace(struct Trace *trace);

#endif
