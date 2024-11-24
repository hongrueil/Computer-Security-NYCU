#include <stdio.h> 
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h> 
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>



typedef struct iphdr iph;
typedef struct udphdr udph;

typedef struct //for check sum
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}ps_hdr;

typedef struct
{
 unsigned short id;   // ID
 unsigned short flags; // DNS Flags
 unsigned short qcount; // Question Count
 unsigned short ans;  // Answer Count
 unsigned short auth; // Authority RR
 unsigned short add;  // Additional RR
}dns_hdr;

typedef struct
{
 unsigned short qtype;
 unsigned short qclass;
}query;


unsigned short csum(unsigned short *ptr,int nbytes) 
{
 register long sum;
 unsigned short oddbyte;
 register short answer;

 sum=0;
 while(nbytes>1) {
  sum+=*ptr++;
  nbytes-=2;
 }
 if(nbytes==1) {
  oddbyte=0;
  *((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
  sum+=oddbyte;
 }

 sum = (sum>>16)+(sum & 0xffff);
 sum = sum + (sum>>16);
 answer=(short)~sum;
 
 return(answer);
}

void dns_format(char * buff, const char * hostname)  // for change hostname into right format
{
    printf("in format ");
    char record[50];

    strncpy(record, hostname, 50);
    strncat(record, ".", 2);

    for (uint16_t i = 0, j = 0; record[i]; i++) {
        if(record[i] == '.') {
            *buff++ = i - j;
            for(; j < i; j++) {
                *buff++ = record[j];
            }
            j++;
        }
    }
    *buff++ = '\0';
    
  
}

void dns_hdr_create(dns_hdr *dns) //藉由看 wireshark 來看出 query 要怎麼填
{
    printf("in create ");
 dns->id = (unsigned short) htons(0XEE1B); //716315 = 0xAEEB query ID
 dns->flags = htons(0x0100);
 dns->qcount = htons(1);
 dns->ans = 0;
 dns->auth = 0;
 dns->add = 0;
}

void dns_send(char *trgt_ip, int trgt_p, char *dns_srv, int dns_p, unsigned char *dns_record)
{
    printf("in send" );
    // Building the DNS request data packet

    unsigned char dns_data[128];

    dns_hdr *dns = (dns_hdr *)&dns_data;
    dns_hdr_create(dns);

    unsigned char *dns_name, dns_rcrd[32];
    dns_name = (unsigned char *)&dns_data[sizeof(dns_hdr)];
    strcpy(dns_rcrd, dns_record);
    dns_format(dns_name , dns_rcrd);
    printf("%s/n",dns_name);


    query *q;
    q = (query *)&dns_data[sizeof(dns_hdr) + (strlen(dns_name)+1)];
    q->qtype = htons(0x00ff);
    q->qclass = htons(0x1);

 
 
 // Building the IP and UDP headers

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dns_p);
    sin.sin_addr.s_addr = inet_addr(dns_srv);
    printf("126 ");
    
    int total_len = 0;
    unsigned char buffer[65535];
    memset(buffer,0,65536);

    struct iphdr *iph = (struct iphdr*)&buffer;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->id = htons(10201);
    iph->ttl = 64;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    iph->protocol = IPPROTO_UDP;
    
    iph->check = csum((unsigned short *)buffer, iph->tot_len);
    iph->saddr = inet_addr(trgt_ip);
    iph->daddr = inet_addr(dns_srv); // put destination IP address
    
    total_len += sizeof(struct iphdr);
    printf("%d",total_len);


    struct udphdr *uh = (struct udphdr *)(buffer + total_len);
    uh->source = htons(trgt_p);
    uh->dest = htons(dns_p);
    uh->check = 0;
    uh->len = htons(8+sizeof(dns_hdr)+(strlen(dns_name)+1)+sizeof(query));
    total_len += sizeof(struct udphdr);
    printf("%d",total_len);


    char *data, *psgram;
    data = buffer + total_len;
    memcpy(data, &dns_data, sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) +1);
    total_len += sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) +1;
    printf("\n");
    printf("%d",sizeof(dns_hdr));
   /* for (int i=0;i<total_len;i++){
        printf("%c",buffer[i]);
    }*/
    printf("\n");

 // Pseudoheader creation and checksum calculation
    ps_hdr pshdr;
    pshdr.saddr = inet_addr(trgt_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(struct udphdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));
    printf("166 ");
 int pssize = sizeof(ps_hdr) + sizeof(struct udphdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    psgram = malloc(pssize);
 
    memcpy(psgram, (char *)&pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), uh, sizeof(struct udphdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));
    printf("172 ");
    uh->check = csum((unsigned short *)psgram, pssize);
    printf("174 ");
    // Send data
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd==-1) perror("Could not create socket.");
    else sendto(sd, buffer, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    printf("%ld\n",iph->tot_len);
    for (int i=0;i<iph->tot_len;i++){
        printf("%d ",buffer[i]);
    }
    printf("\n 179 ");

 return;
}


int main(int argc, char *argv[]){
    char *trgt_ip = argv[1];
    int trgt_p = atoi(argv[2]);
    char *dns_srv = argv[3];
    char *dns_record ="www.google.com";
    for(int i =0;i<3;i++){
    dns_send(trgt_ip,trgt_p,dns_srv,53,dns_record);}
    /*printf("%s \n",trgt_ip);
    printf("%d \n", trgt_p);
    printf("%s \n",dns_srv);*/

    




};