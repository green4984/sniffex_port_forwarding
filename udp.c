#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#define BUFLEN 38
#define PORT 8848
typedef struct ip_hdr{//ipv4头部 
    unsigned int ip_length:4; /*little-endian*/ 
    unsigned int ip_version:4; 
    unsigned char ip_tos; 
    unsigned short ip_total_length; 
    unsigned short ip_id; 
    unsigned short ip_flags; 
    unsigned char ip_ttl; 
    unsigned char ip_protocol; 
    unsigned short ip_cksum; 
    unsigned int ip_source; 
    unsigned int ip_dest; 
}ip_hdr;
typedef struct udp_hdr{//udp头部
    unsigned short s_port;
    unsigned short d_port;
    unsigned short length;
    unsigned short cksum;
}udp_hdr;

typedef struct psd_header{//伪头部，用于计算校验和

    unsigned int s_ip;//source ip

    unsigned int d_ip;//dest ip

    unsigned char mbz;//0

    unsigned char proto;//proto type

    unsigned short plen;//length

}psd_header;

void swap(unsigned int *a, unsigned int *b)//交换
{
    *a = (*a)^(*b);
    *b = (*a)^(*b);
    *a = (*a)^(*b);
}

unsigned short checksum(unsigned short* buffer, int size)//校验和
{
    unsigned long cksum = 0;
    while(size>1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if(size)
    {
        cksum += *(unsigned char*)buffer;
    }
        cksum = (cksum>>16) + (cksum&0xffff); //将高16bit与低16bit相加

        cksum += (cksum>>16); //将进位到高位的16bit与低16bit 再相加

    return (unsigned short)(~cksum);
}
int main(int argc, char *argv[])
{
    char buf[BUFLEN];
    int sockfd = -1;
    
    struct sockaddr_in host_addr;
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP))<0)
    {
        printf("socket() error!\n");
        exit(1);
    }
    memset(&host_addr, 0, sizeof(host_addr));
    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(PORT);
    host_addr.sin_addr.s_addr = inet_addr("200.200.30.42");

    const int on = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))<0)
    {
        printf("setsockopt() error!\n");
        exit(0);    
    }
    
    int addr_len = sizeof(host_addr);

    while(1)
    {    
        ip_hdr *iphdr;
        iphdr = (ip_hdr*)buf;
        udp_hdr *udphdr;
        udphdr = (udp_hdr*)(buf+20);
        iphdr->ip_length = 5;
        iphdr->ip_version= 4;
        iphdr->ip_tos = 0;
        iphdr->ip_total_length = htons(sizeof(buf));
        iphdr->ip_id = 0;
        iphdr->ip_flags = 0x40;
        iphdr->ip_ttl = 0x40;
        iphdr->ip_protocol = 0x11;
        iphdr->ip_cksum = 0;
        iphdr->ip_source = inet_addr("10.95.38.12");//源地址
        iphdr->ip_dest = inet_addr("10.95.38.13");//目的地址
        iphdr->ip_cksum = checksum((unsigned short*)buf, 20);
        udphdr->s_port = htons(8443);//源端口
        udphdr->d_port = htons(514);//目的端口
        udphdr->length = htons(sizeof(buf)-20);
        udphdr->cksum = 0;
        psd_header psd;
        psd.s_ip = iphdr->ip_source;
        psd.d_ip = iphdr->ip_dest;
        psd.mbz = 0;
        psd.proto = 0x11;
        psd.plen = udphdr->length;
        char tmp[sizeof(psd)+ntohs(udphdr->length)];
        memcpy(tmp, &psd, sizeof(psd));
        memcpy(tmp+sizeof(psd), buf+20, sizeof(buf)-20);
        udphdr->cksum = checksum((unsigned short*)tmp, sizeof(tmp));
        int res =sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&host_addr, sizeof(host_addr));
        sleep(1);
    } 
    return 0;

}
