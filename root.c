#include "client.h"
#include "local_server.h"
#include "root.h"


int main(){
	int sockup;
	struct sockaddr_in localAddr;
	struct sockaddr_in upAddr;
	unsigned int upAddrLen;
	char upInBuffer[DNS_MAX_LENGTH];
	char upOutBuffer[DNS_MAX_LENGTH];
	char splitName[100];
	char ipAddr[100];
	//接收的结构体
	dns_query *recvQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(recvQuery);
	dns_header *recvHead = (dns_header *)malloc(sizeof(dns_header));initHead(recvHead);
	//回应的结构体 
	dns_query *resQuery = (dns_query *)malloc(sizeof(dns_query));initQuery(resQuery);
	dns_header *resHead = (dns_header *)malloc(sizeof(dns_header));initHead(resHead);
	dns_rr *resRecord = (dns_rr *)malloc(sizeof(dns_rr));initRR(resRecord);
	unsigned short port=53;
	int recvMsgSize;
	int outMsgSize; 
	char *input;
	char *output;
	
	if((sockup=socket(PF_INET,SOCK_DGRAM,0))<0)  printf("socket() failed\n");
	
	init_sockaddr_in(ROOT_SERVER_IP, 53000, &localAddr);
	if((bind (sockup,(struct sockaddr*)&localAddr,sizeof(localAddr)))<0){
		printf("bind() failed\n");
	} 
	while(1){
	upAddrLen=sizeof(upAddr);
	//receive
	if((recvMsgSize=recvfrom(sockup,upInBuffer,DNS_MAX_LENGTH,0,(struct sockaddr*)&upAddr,&upAddrLen))<0){
		printf("recvfrom() failed\n");
	}
	printf("Handling client %s\n",inet_ntoa(upAddr.sin_addr));
	
	
	//解析localServer传过来的数据 
	input = upInBuffer;
	input += getHeader(input, recvHead);
	input += getQuery(input, recvQuery); 	
	printf("The domain name is: %s\n", recvQuery->name);
	//printf("The First Class Name is: %s\n", splitOneDomainName(recvQuery->name));
	splitOneDomainName(recvQuery->name, splitName);
	
	//解析部分至上就结束了，以下为回应部分
	resHead->id =htons(recvHead->id);
	resHead->flags =htons(0x8000);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
	resHead->authorNum = 0;
	resHead->addNum = 0;
	resQuery = recvQuery;
	resRecord->name[0]=recvQuery->name;
    resRecord->rclass=recvQuery->qclass;
	resRecord->type=A;
	resRecord->ttl = (uint32_t)86400;
	resRecord->length = 4;
	
	/*
	 *返回一级域ip 
	 */
	if(isequal(splitName,"com")||isequal(splitName,"org")){
	    //在结构体里把rdata赋值为ip（127.0.0.4） ,在head里把anwernum赋值为0 
	    //printf("hello, in org!\n");
	    strcpy(ipAddr, "127.0.0.4");
	   // printf("hello,%s\n", ipAddr);
	    char *p = ipAddr;
	    int len = strlen(ipAddr)+1;
	    resRecord->rdata=(char*)malloc(len*sizeof(char));
	    //printf("hello, in org!\n");
	    memcpy(resRecord->rdata,p,len);
	    //printf("resRecordDataL %s\n", resRecord->rdata);
	   // printf("hello, in org!\n");
	    //strcpy(resRecord->rdata, "127.0.0.4");
		output = upOutBuffer; 
	 	output += head2buf(output, resHead);
	 	output += query2buf(output,resQuery); 
		output += rr2buf(output,resRecord);
	    
	    
	}
	else if(isequal(splitName,"cn")||isequal(splitName,"us")){
		 //在结构体里把rdata赋值为ip（127.0.0.5）,在head里把anwernum赋值为0
		strcpy(ipAddr, "127.0.0.5");
		char *p = ipAddr;
	    int len = strlen(ipAddr)+1;
	    resRecord->rdata=(char*)malloc(len*sizeof(char));
	    //printf("hello, in org!\n");
	    memcpy(resRecord->rdata,p,len);
	    //printf("resRecordDataL %s\n", resRecord->rdata);
		output = upOutBuffer; 
	 	output += head2buf(output, resHead);
	 	output += query2buf(output,resQuery); 
		output += rr2buf(output,resRecord);
	 	//int p = 0;
	 	// while(1){
	 	// printf("%hu\n", upOutBuffer[p]);
	 	// p++;
	 	// if(p>100) break;
	 	// }
	 	// printf("\n");
	} 
	else{
		resHead->answerNum = 0;
		resHead->flags =htons(0x8183);
		output = upOutBuffer; 
	 	output += head2buf(output, resHead);
	 	output += query2buf(output,resQuery); 
		//rdata无数值，anwernum为0
		//查询失败 
	} 
	 
	
	//send
	//strcpy(upOutBuffer,"DASHABI");
	outMsgSize=output - upOutBuffer +1;
	//printf("length:%d \n",outMsgSize);
	if(sendto(sockup,upOutBuffer,outMsgSize,0,(struct sockaddr*)&upAddr,sizeof(upAddr))!=outMsgSize){
		printf("sendto() problem!\n");
	}
	
	}	
}