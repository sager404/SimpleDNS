#include "local_server.h"
#include "client.h"
#include "dns.h"

int main() {
    struct sockaddr_in client_addr;
    init_client_addr(&client_addr);
    struct sockaddr_in local_server_addr;
    init_local_addr(&local_server_addr);
    struct sockaddr_in root_server_addr;
    init_addr(&root_server_addr, ROOT_SERVER_IP);

    int sock = udp_socket();

    char name[127] = {0};
    char packet[BUFSIZE] = {0};

    unsigned int client_addr_len = sizeof(client_addr);
    if (bind(sock, (struct sockaddr *)&local_server_addr,
             sizeof(local_server_addr)) < 0) {
        perror("local-server: bind failed");
    }
    if (recvfrom(sock, packet, sizeof(packet), 0,
                 (struct sockaddr *)&client_addr, &client_addr_len) < 0) {
        perror("Revieve from client failed");
    }
    struct DNS_Header *header = (struct DNS_Header *)packet;
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));
    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));

    int offset = parse_query_packet(packet, header, query, name);
    char data[127] = {0};
    if (get_local_cache(name, data, rr)) {
        printf("%s", query->name);
        add_rr(packet, rr, offset + 1);
        gen_response_packet(packet, header, 1);
        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&client_addr,
               sizeof(client_addr));
        free(query);
        free(rr);
    } else {
        if (!connect(sock, (struct sockaddr *)&root_server_addr,
                     sizeof(root_server_addr))) {
            if (send(sock, packet, BUFSIZE, 0) < 0) {

                perror("local_server: send root_server failed");
            }else{
                recv(sock, packet, BUFSIZE, 0);
            }

        } else {
            perror("local_server:connect root_server failed");
        }
    }
    free(&client_addr);
    free(&local_server_addr);
    free(&root_server_addr);
    close(sock);
}
