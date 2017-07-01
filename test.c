#include <pcap.h>
#include <stdio.h>  
#include <string.h>  
#include <stdlib.h>  
#include <ctype.h>  
#include <errno.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
/* default snap length (maximum bytes per packet to capture) */  
#define SNAP_LEN 1518  
  
/* ethernet headers are always exactly 14 bytes [1] */  
#define SIZE_ETHERNET 14  
  
/* Ethernet addresses are 6 bytes */  
#define ETHER_ADDR_LEN  6  


char errbuf[PCAP_ERRBUF_SIZE] = {0}; // 出错信息  

char *get_dev();
pcap_t *get_handler(char *);

struct psdhdr
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t  zero;
    u_int8_t  protocol;
    u_int16_t len;
};

void  print_payload (const u_char * payload, int len)  
{  

	int len_rem = len;  
	int line_width = 16;      /* number of bytes per line */  
	int line_len;  
	int offset = 0;       /* zero-based offset counter */  
	const u_char *ch = payload;  

	if (len <= 0)  
		return;  

	/* data fits on one line */  
	if (len <= line_width)  
	{  
		print_hex_ascii_line (ch, len, offset);  
		return;  
	}  

	/* data spans multiple lines */  
	for (;;)  
	{  
		/* compute current line length */  
		line_len = line_width % len_rem;  
		/* print line */  
		print_hex_ascii_line (ch, line_len, offset);  
		/* compute total remaining */  
		len_rem = len_rem - line_len;  
		/* shift pointer to remaining bytes to print */  
		ch = ch + line_len;  
		/* add offset */  
		offset = offset + line_width;  
		/* check if we have line width chars or less */  
		if (len_rem <= line_width)  
		{  
			/* print last line and get out */  
			print_hex_ascii_line (ch, len_rem, offset);  
			break;  
		}  
	}  

	return;  
} 

char * get_dev()
{
	char *dev = NULL;
	pcap_t *handle = NULL;
	dev = pcap_lookupdev(errbuf);  
	if (NULL == dev) {  
		printf(errbuf);
		exit(0);
	}
	return dev;
}

pcap_t *get_handler(char *dev)
{
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	}
	return handle;
}

void set_filter(pcap_t *handle, struct bpf_program *fp, char *filter_exp, bpf_u_int32 net)
{
	if (pcap_compile(handle, fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}
	if (pcap_setfilter(handle, fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */  
	const struct sniff_ethernet *ethernet;    /* The ethernet header [1] */  
	const struct sniff_ip *ip;    /* The IP header */  
	const struct sniff_tcp *tcp;  /* The TCP header */  
	const struct sniff_udp *udp;  /* The UDP header */  
	const char *payload;      /* Packet payload */  

	int size_ip;  
	int size_tcp;  
	int size_payload;  

	/* define ethernet header */  
	ethernet = (struct sniff_ethernet *) (packet);  

	/* define/compute ip header offset */  
	ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);  
	size_ip = IP_HL (ip) * 4;  
	if (size_ip < 20)  
	{  
		printf ("   * Invalid IP header length: %u bytes\n", size_ip);  
		return;  
	}  

	if (ip->ip_p != IPPROTO_UDP)  {
		return;
	}
	/* define/compute udp header offset */  
	udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);  
	printf ("   Src port: %d\n", ntohs (udp->sport));  
	printf ("   Dst port: %d\n", ntohs (udp->dport));  
	printf ("udp length:%d\n", ntohs (udp->udp_length));  
	printf ("udp sum:%d\n", ntohs (udp->udp_sum));  
	/* define/compute udp payload (segment) offset */  
	payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + 8);  
	size_payload = ntohs (ip->ip_len) - (size_ip + 8);  

	/* 
	 *        * Print payload data; it might be binary, so don't just 
	 *               * treat it as a string. 
	 *                      */  
	if (size_payload > 0)  
	{  
		printf ("   Payload (%d bytes):\n", size_payload);  
		print_payload (payload, size_payload);  
	}  

}


int main()
{
	char *dev = NULL;
	pcap_t *handle = NULL;
	struct bpf_program fp;
	char filter_exp[] = "port 443";
	bpf_u_int32 mask;
	bpf_u_int32 net;

	dev = get_dev();
	handle = get_handler(dev);
	printf("listening device: %s ...\n", dev);
	set_filter(handle, &fp, filter_exp, net);
	// main loop
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_freecode (&fp);  
	pcap_close (handle);  
	return 0;
}
