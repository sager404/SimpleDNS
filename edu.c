#include "edu.h"


int main(){
    int sock;
    struct sockaddr_in eduAddr; //本服务器
    struct sockaddr_in localAddr; //下一级服务器
    unsigned int serAddrLen; //下一级服务器地址长度
    unsigned char packetIn[BUFSIZE];
	unsigned char packetOut[BUFSIZE];	
    int recvMsgSize;
    int outMsgSize; 
	char* file = "edu.txt";
	//不需要分割名字，因为已经是最底层服务器，拿文件查询即可 

    init_addr(&eduAddr, SCD1_SERVER_IP);
    sock = tcp_socket();
    server_bind(sock, &eduAddr);
    tcp_listen(sock);

    while(1){
    int client_sock = tcp_accept(sock, &localAddr);
    tcp_receive(client_sock, packetIn);

    //接受的结构体 
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));
	
	//解析
	char *i = packetIn;
	int header_len = deserialize_header(i + 2, recvHead);
    int query_len = deserialize_query(i + 2 + header_len, recvQuery); 	
	printf("The domain name is: %s\n", recvQuery->name);
	
	
	/*
	 *返回查询结果 
	 */
	memcpy(packetOut,packetIn,BUFSIZE);
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));
	dns_header *resHead = (struct DNS_Header *)(packetOut+2);
	unsigned short q_len = parse_query_packet(packetOut+2,resHead,resQuery);
	unsigned short len = 14;
	if(load_data(packetOut, resQuery, &len, file)){
		resHead->flags=htons(FLAGS_RESPONSE);
		short n_len = htons(len);
		memcpy(packetOut, &n_len,2);
		tcp_send(client_sock, packetOut, len);
	}else{
		short n_len = htons(q_len);
		memcpy(packetOut, &n_len,2);
		resHead->flags=htons(FLAGS_NOTFOUND);
		tcp_send(client_sock, packetOut, q_len+2);
	}
	close(client_sock);
	}  
	close(sock);
}	