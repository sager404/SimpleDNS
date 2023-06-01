#include "server.h"
#include "dns.h"
#include <sys/types.h>

void gen_tcp_packet(char *packet, int len){
        char tmp[BUFSIZE] = {0};
        memcpy(tmp, packet, len);
        memcpy(packet, &len, 2);
        memcpy(packet+2, tmp, len);
}

void update_packet_len(char *packet){
    u_int16_t len = cal_packet_len(packet+2);
    memcpy(packet, &len, 2);
}