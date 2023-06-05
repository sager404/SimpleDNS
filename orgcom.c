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
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
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
	
	//以下为回应的部分
	resHead->id =htons(recvHead->id);
	resHead->flags =htons(0x8000);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); 
	resHead->authorNum = 0;
	resHead->addNum = 0;
	resQuery = recvQuery;
	resRecord->name=recvQuery->name;
    resRecord->rclass=recvQuery->qclass;
	resRecord->type=recvQuery->qtype;
	resRecord->ttl = (uint32_t)86400;
	resRecord->length = 4;
	
	/*
	 *返回查询结果 
	 */
	memcpy(packetOut,packetIn,BUFSIZE);
	if(get_ORGCOM(packetOut, recvQuery, 14+query_len)){
		unsigned int len_p = htons(cal_packet_len(packetOut+2));
		struct DNS_Header *header = (struct DNS_Header *)(packetOut+2);
		header->flags=htons(FLAGS_RESPONSE);
		memcpy(packetOut, &len_p, 2);
		tcp_send(client_sock, packetOut, len_p+2);
	}
	}   
}	





