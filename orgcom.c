#include "dns.h"
#include "client.h"
#include "local_server.h"
#include "orgcom.h"

int main(int argc, char *argv[]){
    int sock;
    struct sockaddr_in localAddr;
    struct sockaddr_in serverAddr;
    char buffer[BUFSIZE];
    int recvMsgSize;

    bzero(&localAddr,sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = inet_addr(ORGCOM_SERVER_IP);
    localAddr.sin_port = htons(0); 
    int client_socket = socket(AF_INET,SOCK_STREAM,0);
    if(client_socket < 0)
    {
        printf("Create socket failed!\n");
        exit(1);
    }
    if(bind(client_socket,(struct sockaddr*)&localAddr,sizeof(localAddr)))
    {
        printf("Client bind port failed!\n");
        exit(1);
    }

    bzero(&serverAddr,sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    if(0 == inet_aton(argv[1],&serverAddr.sin_addr))
    {
        printf("Server IP Address Error!\n");
        exit(1);
    }
    serverAddr.sin_port = htons(DNS_PORT);
    socklen_t server_addr_length = sizeof(serverAddr);
    if(connect(client_socket,(struct sockaddr*)&serverAddr, server_addr_length) < 0)
    {
        printf("Can Not Connect To %s!\n",argv[1]);
        exit(1);
    }

}