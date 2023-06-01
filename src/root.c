#include "root.h"

void initHead(dns_header *head){
	head->id=0;
	head->flags=0;
	head->queryNum=0;
	head->answerNum=0;
	head->authorNum=0;
	head->addNum=0;
}


void initQuery(dns_query *query){
	//printf("Hello\n"); 
	if(query->name!=NULL){
		printf("hi\n");
		free(query->name);
		query->name=NULL;
	}
	//printf("end\n"); 
	query->qtype=0;
	query->qclass=0;
}


void initRR(dns_rr *rr){
	if(rr->name!=NULL){
		free(rr->name);
		rr->name=NULL;
	}
	if(rr->rdata!=NULL){
		free(rr->rdata);
		rr->rdata=NULL;
	}
	rr->type=0;
	rr->rclass=0;
	rr->ttl=0;
	rr->length=0;
}

 int isequal(char *str1, char* str2)
{
    if (strlen(str1)!=strlen(str2))
     return 0;
     int i=0;
    for (i = 0; str1[i]!='\0'; i++){
        if (str1[i]!=str2[i])
        return 0;
     }
   return 1;
  }

void init_sockaddr_in(char* ip, int port, struct sockaddr_in* addr){
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr=inet_addr(ip);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
}

unsigned int getHeader(char *q, dns_header *header){
	// int i = 0;
	// while(1){
	// 	if(i<100){
	// 		printf("headerIn: %d\n", q[i]);i++;
	// 	}
		
	// 	else break;
	// }
	
	header->id = ntohs(*(uint16_t*) (q));
	header->flags = ntohs(*(uint16_t*) (q+2));
	header->queryNum = ntohs(*(uint16_t*) (q+4));
	//printf("queryName: %d\n", header->id);
	header->answerNum = ntohs(*(uint16_t*) (q+6));
	header->authorNum = ntohs(*(uint16_t*) (q+8));
	header->addNum = ntohs(*(uint16_t*) (q+10));
	
	return sizeof(dns_header);
}



unsigned int getQuery(char *q, dns_query *query){
	char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	//printf("d: %s\n", d);
	uint8_t count = 0;
	int i = 0; 
	//count = ntohs(*(uint8_t*)(q));
	//完成报文中数字加域名形式至点分值的转换 
	while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			//("count:%d\n", count);
			q++;
			while(count){
				//printf("i: %d\n", i);
				//printf("char1:%c\n", *q);
				memcpy(&(domainName[i]), q, sizeof(char));
				//printf("domain name i: %c\n", domainName[i]);
				count--; q++; i++;
			}
			domainName[i] = '.'; //加点 
			i++;
		}
		else{
			domainName[i-1] = '\0'; //标注结束 
			q++; 
			break;
		}
	}
	// printf("i: %d\n", i);  
	// printf("Converted domain name: %s\n", domainName);
	// printf("length: %d\n", i);
	query->name = (char*)malloc(i*sizeof(char));
	memcpy(query->name, domainName, i); //此时的i便为转换后变长字符串的长度了，经过了循环遍历 
	//printf("Query name: %s\n", query->name);
	
	query->qtype = ntohs(*(uint16_t*) (q));
	query->qclass = ntohs(*(uint16_t*) (q+2));
	//printf("Query Type: %d\n", query->qtype);
	//printf("Query Class: %d\n", query->qclass);
	return i+4+1; //补一个1的原因是网络的域名形式和转换后的差一位 
}

void splitOneDomainName(char *domainName, char *splitName){
	int i = strlen(domainName)-1; //免去\0的影响 
	//printf("domainName: %s\n", domainName);
	int j = 0;
	int k = 0;
	char invertName[100];
	char splitOneName[100];
	memset(invertName, 0, 100);
	memset(splitOneName, 0, 100);
	while(1){
		if(domainName[i]!='.'){
			//printf("d: %c\n", domainName[i]);
			invertName[j] = domainName[i];
			//printf("s: %c\n", invertName[j]);
			i--;j++; 
		}else break;
	}
	invertName[j] = '\0';
	//printf("splitOneInvert: %s\n", invertName);
	i = strlen(invertName)-1;
	while(1){
		if(k < strlen(invertName)){
			////printf("s: %c\n", invertName[i]);
			splitName[k] = invertName[i];
			i--; k++;
		}else break;
		
	}
	splitName[k] = '\0';
	
	//printf("splitOne: %s\n", splitName);
}

unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));

	return sizeof(dns_header);
}

unsigned int query2buf(char *o, dns_query *query){
	char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		//printf("get: %c\n", query->name[i]);
		if(query->name[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				//printf("Count: %d\n", count);
				count = 0;
				o++; i++;
				tempts = 1;
				
		}
		else if(query->name[i] == '\0'){
			memcpy(o, &(query->name[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(query->name[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
	o++;
	int len = o - ini; //计算出名字的长度
	//printf("length: %d\n", len); 
	uint16_t temp = htons(query->qtype);
	memcpy(o, &temp, sizeof(short));
	temp = htons(query->qclass);
	o+=sizeof(short);
	memcpy(o, &temp, sizeof(short));
	o+=sizeof(short);
//	int p=0;
//	while(p<=100){
//	printf("buff1: %hu\n", o[p]);
//	p++;
//	}
	//printf("length22: %d\n",  len+2*sizeof(short)); 
	return len+2*sizeof(short);
}

unsigned int rr2buf(char *o, dns_rr* rr) {
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49164); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
//	printf("rr2leng: %d\n", strlen(rr->name));
//	memcpy(o,rr->name,strlen(rr->name)+1);
//	while(1){
//		printf("ccc: %c\n", o[i]);
//		i++;
//		if(i == 5) break;
//	}
//	printf("rrName: %s\n", o);
	o+=2;
	
	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	//printf("rrType: %d\n", rr->type);
	o+=2;
	
	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	
	temp32=htonl(rr->ttl); //这里是htonl 32位数字的主机字节序转化 
	//printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;
	
	temp=htons(rr->length);
	memcpy(o, &temp, sizeof(short));
	o+=2;
	
	uint32_t  ipAddr = inet_addr(rr->rdata);
	memcpy(o, &ipAddr,rr->length); //将字符串转化为网络字节序的4bytes数据 
	//printf("rrDate: %s\n", o);
	o+=rr->length; //也就是要移动4位 
	return 11+strlen(rr->name)+(rr->length);
}