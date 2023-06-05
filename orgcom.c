#include "socket.h"
#include "orgcom.h"
#include "server.h"
#include "socket.h"

int main(){
    int sock;
    int state=0;  //查到没有 
    struct sockaddr_in localAddr; //本服务器
    struct sockaddr_in serverAddr; //下一级服务器
    unsigned int serAddrLen; //下一级服务器地址长度
    char packetIn[BUFSIZE];
	char packetOut[BUFSIZE];	
    int recvMsgSize;
    int outMsgSize; 
	char ipAddr[100];
	//不需要分割名字，因为已经是最底层服务器，拿文件查询即可 

    init_addr(&localAddr, TLD1_SERVER_IP);
    sock = tcp_socket();
    server_bind(sock, &localAddr);
    tcp_listen(sock);

    while(1){
    int client_sock = tcp_accept(sock, &serverAddr);
    tcp_receive(client_sock, packetIn);

    //接受的结构体 
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	dns_rr *recvrRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(recvrRecord);  
	//回应的结构体 

	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	//MX第二次查询ip
	dns_query *mxQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(mxQuery);
	dns_header *mxHead = (dns_header *)malloc(sizeof(dns_header));initHead(mxHead);
	dns_rr *mxRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(mxRecord);
	
	
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
	int len = parse_query_packet(packetOut+2,resHead,resQuery);
	if(get_ORGCOM(packetOut+2, resQuery, len)){
		unsigned int len_p = htons(cal_packet_len(packetOut+2));
		resHead->flags=htons(FLAGS_RESPONSE);
		memcpy(packetOut, &len_p, 2);
		tcp_send(client_sock, packetOut, len_p+2);
	}
	}   
	close(sock);
	
}	





