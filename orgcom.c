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
    char packetOut[BUFSIZE];
    char packetIn[BUFSIZE];
    int recvMsgSize;
    int outMsgSize; 
	char ipAddr[100];
	//不需要分割名字，因为已经是最底层服务器，拿文件查询即可 

    sock = tcp_socket();
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
	i += getHeader(i, recvHead);
	i += getQuery(i, recvQuery); 	
	printf("The domain name is: %s\n", recvQuery->name);
	
	//以下为回应的部分
	resHead->id =htons(recvHead->id);
	resHead->flags =htons(0x8000);
	resHead->queryNum =htons(recvHead->queryNum);
	resHead->answerNum = htons(1); //这里不一定是1，若没查到怎么办？？ 
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
	 if(recvQuery->qtype==A) {
	   freopen("orgcomA.txt", "r", stdin);
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_ip[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_ip)){
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class: %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_ip);

				resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_ip)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_ip);
				resHead->answerNum = htons(1);
				resRecord->length=strlen(resRecord->rdata)+1;
				resHead->flags = htons(0x8180);

	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
	    		state=1;   //表明查到 
	    		break;
			}
		}   
	}
	else if(recvQuery->qtype==CNAME){
		freopen("orgcomC.txt", "r", stdin);
	   char file_name[255],file_ttl[255],file_class[255],file_type[255],file_addr[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_addr)){
	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class: %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_addr);

				resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_addr);
				resHead->answerNum = htons(1);
				resRecord->length=strlen(resRecord->rdata)+1;
				resHead->flags = htons(0x8180);
	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
	    		state=1;   //表明查到 
	    		break;
			}
		}   
	}
	else if(recvQuery->qtype==MX){
		freopen("orgcomM.txt", "r", stdin);
	    char file_name[255],file_ttl[255],file_class[255],file_type[255],file_addr[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_addr)){

	    	if(isequal(recvQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class: %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_addr: %s\n",file_addr);

				resRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(resRecord->name, file_name);
				resRecord->ttl = (uint32_t)(atoi(file_ttl));
				resRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(resRecord->rdata, file_addr);
				resHead->answerNum = htons(1);
				//这里用现在的域名减去查询的名字长度再+2(pre..)+2(压缩指针)
		        resRecord->length = strlen(resRecord->rdata)-strlen(recvQuery->name) + 4;
				resHead->flags = htons(0x8180);

	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
	    		state=1;   //表明查到 
	    		break;
			}
		} 
	    if(state==1){
		mxQuery->name = (char*)malloc((strlen(resRecord->rdata)+1)*sizeof(char));
		strcpy(mxQuery->name, resRecord->rdata);
		mxQuery->qclass = recvQuery->qclass;
		mxQuery->qtype = A; //这里要用上一次的结果A方式查询一下
		freopen("comorgA.txt", "r", stdin);
	    char file_ip[255];
	    while(~scanf("%s%s%s%s%s", file_name, file_ttl, file_class,file_type,file_ip)){
	    	if(isequal(mxQuery->name,file_name)){
	    		printf("file_name: %s\n",file_name);
	    		printf("file_name length: %d\n",strlen(file_name));
	    		printf("file_ttl: %s\n",file_ttl);
	    		printf("file_class: %s\n",file_class);
	    		printf("file_type: %s\n",file_type);
	    		printf("file_ip: %s\n",file_ip);
		    	mxRecord->name = (char*)malloc((strlen(file_name)+1)*sizeof(char));
				strcpy(mxRecord->name, file_name);
				mxRecord->ttl = (uint32_t)(atoi(file_ttl));
				mxRecord->rdata = (char*)malloc((strlen(file_addr)+1)*sizeof(char));
				strcpy(mxRecord->rdata, file_ip);
				mxRecord->length=4;
				mxRecord->type=A; 
	            mxRecord->rclass=recvQuery->qclass;
                resHead->addNum = htons(1); 

	    		//printf("recv->Query: %s\n",recvQuery->name);
	    		//在结构体里把rdata赋值为 file_ip ,在head里把anwernum赋值为1，flag为8180 
	    		state=1;   //表明查到 
	    		break;
			}
		    }
	    }
	}	  
	char* o=packetOut;
	//查不到的情况
	if(state==0){
		resHead->flags =htons(0x8183);
		resHead->answerNum = 0;
		o = packetOut; 
	 	o += head2buf(o, resHead);
	 	o += query2buf(o,resQuery);
		//在结构体里把rdata赋值为找不到 ,在head里把anwernum赋值为 1，flag为8183 
	}else{
		o = packetOut; 
	 	o += head2buf(o, resHead);
	 	o += query2buf(o,resQuery); 
	 	o += rr2buf(o,resRecord);
	 	if(recvQuery->qtype == MX)
	 	o+=add2buf(o, mxRecord, recvQuery);
	}


	//统一返回
	//把packetOut赋值 
	outMsgSize = o - packetOut + 1;
	tcp_send(client_sock, packetOut, outMsgSize);
    }
}	





