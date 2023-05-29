#include "client.h"
#include "local_server.h"


int main() {
    struct sockaddr_in client_addr;
    init_client_addr(&client_addr);
    struct sockaddr_in local_server_addr;
    init_local_addr(&local_server_addr);

    int sock_in = udp_socket();

    char name[127] = {0};
    char packet[BUFSIZE] = {0};
    // char packet_res[1023] = {0};
    unsigned int client_addr_len = sizeof(client_addr);
    if (bind(sock_in, (struct sockaddr *)&local_server_addr,
             sizeof(local_server_addr)) < 0) {
        perror("local-server: bind failed");
    }
    int packet_len;
    packet_len = recvfrom(sock_in, packet, sizeof(packet), 0,
                          (struct sockaddr *)&client_addr, &client_addr_len);
    if (packet_len < 0) {
        perror("Revieve from client failed");
    }
    struct DNS_Header *header = (struct DNS_Header *)packet;
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));
    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
    // strcpy(packet_res, packet_query);

    int offset = parse_query_packet(packet, header, query, name);
    char data[127] = {0};
    if (get_local_cache(name, data, rr)) {
        printf("%s", query->name);
        add_rr(packet, rr, offset + 1);
        gen_response_packet(packet, header, 1);
        sendto(sock_in, packet, sizeof(packet), 0,
               (struct sockaddr *)&client_addr, sizeof(client_addr));
        free(query);
        free(rr);
    }
}
