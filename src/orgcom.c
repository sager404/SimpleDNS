#include "orgcom.h"
#include "dns.h"

void initHead(dns_header *head){
	head->id=0;
	head->flags=0;
	head->queryNum=0;
	head->answerNum=0;
	head->authorNum=0;
	head->addNum=0;
}


void initQuery(dns_query *query){
	if(query->name!=NULL){
		printf("hi\n");
		free(query->name);
		query->name=NULL;
	}
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

unsigned int head2buf(char *o, dns_header *head){
	memcpy(o, head, sizeof(dns_header));
	//////////////////////////////////////////////没转主机字节序！！！！！ 
	return sizeof(dns_header);
}

unsigned int getHeader(char *q, dns_header *header){

	header->id = ntohs(*(uint16_t*) (q));
	header->flags = ntohs(*(uint16_t*) (q+2));
	header->queryNum = ntohs(*(uint16_t*) (q+4));
	header->answerNum = ntohs(*(uint16_t*) (q+6));
	header->authorNum = ntohs(*(uint16_t*) (q+8));
	header->addNum = ntohs(*(uint16_t*) (q+10));
	
	return sizeof(dns_header);
}

unsigned int getQuery(char *q, dns_query *query){
	char domainName[100];
	memset(domainName, 0, 100);
	char *d = domainName;
	uint8_t count = 0;
	int i = 0; 

	//完成报文中数字加域名形式至点分值的转换 
	while(1){
		if(*q!='\0'){
			count = *(uint8_t*)(q);
			q++;
			while(count){
				memcpy(&(domainName[i]), q, sizeof(char));
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
	query->name = (char*)malloc(i*sizeof(char));
	memcpy(query->name, domainName, i); //此时的i便为转换后变长字符串的长度了，经过了循环遍历 

	
	query->qtype = ntohs(*(uint16_t*) (q));
	query->qclass = ntohs(*(uint16_t*) (q+2));

	return i+4+1; //补一个1的原因是网络的域名形式和转换后的差一位 
}

unsigned int query2buf(char *o, dns_query *query){
	char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		if(query->name[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
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
	return len+2*sizeof(short);
}

unsigned int rr2buf(char *o, dns_rr* rr) {
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49164); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
	
	o+=2;

	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	printf("rrType: %d\n", rr->type);
	o+=2;

	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	temp32=htonl(rr->ttl); //这里是htonl 32位数字的主机字节序转化 
	printf("ttlconvert: %d\n", temp32);
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;

	temp=htons(rr->length);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	//这里指preference，MX里面要多两个字节哦
	if(rr->type == MX){
		temp=htons(1);
		memcpy(o, &temp, sizeof(short));
		o+=2;
	}
	
	if(rr->type == A){
		uint32_t  ipAddr = inet_addr(rr->rdata);
		memcpy(o, &ipAddr,rr->length); //将字符串转化为网络字节序的4bytes数据 
		o+=rr->length; //也就是要移动4位 
		return 16;
	}
	else if(rr->type == CNAME){
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		if(rr->rdata[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				count = 0;
				o++; i++;
				tempts = 1;
				
		}
		else if(rr->rdata[i] == '\0'){
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
		return 12 + rr->length + 1;
	}
	else if(rr->type == MX){ //MX的情况
		char* ini = o; //for initial
	uint8_t count = 0;
	int i = 0;
	int j = 1; //转换后计数 
	int tempts = 0;
	o++; //先往后移动一位 
	while(1){
		if(rr->rdata[i] == '.'){
				memcpy(o-count-1, &count, sizeof(char));
				count = 0;
				o++; i++;
				tempts = 1;
				break;
				
		}
		else if(rr->rdata[i] == '\0'){
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			memcpy(o-count-1, &count, sizeof(char));
			count = 0;
			break;
		}
		else{
			memcpy(o, &(rr->rdata[i]), sizeof(char));
			o++;
			i++;
			count++; 
		}
	}
	o--;
	temp =  htons(49164); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
	return 16+i;
	}
	
	
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
  
  //用于MX的ip查询，放到addtion里面
unsigned int add2buf(char *o, dns_rr* rr, dns_query* query) {
	int i = 0;
	uint16_t temp;
	uint32_t temp32;
	temp =  htons(49152+12+strlen(query->name)+2+4+14); //这里指代1100000000001100，DNS报文中压缩指针的操作
	memcpy(o, &temp, sizeof(short)); 
	o+=2;
	temp=htons(rr->type);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	temp=htons(rr->rclass);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	temp32=htonl(rr->ttl); //这里是htonl 32位数字的主机字节序转化 
	memcpy(o, &temp32, (2*sizeof(short)));
	o+=4;

	temp=htons(rr->length);
	memcpy(o, &temp, sizeof(short));
	o+=2;

	uint32_t  ipAddr = inet_addr(rr->rdata);
	memcpy(o, &ipAddr, rr->length); //将字符串转化为网络字节序的4bytes数据 
	o+=rr->length; //也就是要移动4位 
	return 16;
}

int get_ORGCOM(char *packet, struct DNS_Query *query, short offset) {
    FILE *fp = fopen("./data/orgcomA.txt", "r");
    if (fp == NULL){
        perror("file open failed");
        return 0;
    }
    struct DNS_Header *header = (struct DNS_Header *)packet;
    short type = ntohs(query->qtype);
    char rname[128] = {0};
    if (ntohs(query->qtype) == PTR) {
        parse_ptr(query->name, rname);
    } else {
        parse_name(query->name, rname);
    }

    char rr_offset = sizeof(struct DNS_Header);
    while (!feof(fp)) {

        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        if (!strcmp(rname, name)) {
            int ntype = get_type(rtype);
            if (ntype == type || ntype == A) {
                struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
                if (ntype == A) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);

                    free(rr);
                    return 1;
                } else if (ntype == PTR) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);

                    free(rr);
                    return 1;
                } else {
                    header->addNum = htons(ntohs(header->addNum) + 1);
                    gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                    offset += add_rr(packet + offset, rr);
                    if (ntype == MX)
                        rr_offset += (14 + strlen(rdata) + 1);
                    else
                        rr_offset += (12 + strlen(rdata) + 1);
                    strcpy(rname, rdata);
                    // type = A;
                }

                free(rr);
            }
        }
    }
    fclose(fp);
    return 0;
}