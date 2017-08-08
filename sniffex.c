#include "sniffex.h"
#include "utils.h"
#include "monitor.h"

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

	return;
}

void handle_packet(u_char *user, const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	int sockfd = *user;
	u_char buffer[SNAP_LEN];
	int len = pkthdr->len;
	struct iphdr* ip;
	struct udphdr* udp;
	char srcbuf[16];
	char dstbuf[16];
	u_char temp[SNAP_LEN];
	struct sockaddr_in addr;
	struct psd_header psdhdr;
	int ip_len;

	memset(buffer,0,SNAP_LEN);
	memset(temp,0,SNAP_LEN);
	memcpy(buffer,packet,len);
	memset(srcbuf,0,16);
	memset(dstbuf,0,16);
	memset(&addr,0,sizeof(struct sockaddr_in));
	memset(&psdhdr,0,sizeof(struct psd_header));

	ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

	ip_len = ntohs(ip->tot_len);
	strcpy(srcbuf,inet_ntoa(((struct ip *)(buffer + sizeof(struct ethhdr)))->ip_src));
	strcpy(dstbuf,inet_ntoa(((struct ip *)(buffer + sizeof(struct ethhdr)))->ip_dst));
	if (debug) {
		printf("source ip:port %s:%d\n", srcbuf, ntohs(udp->source));
		printf("destination ip:port %s:%d\n",dstbuf, ntohs(udp->dest));
		printf("len:%d\n",ip_len);
		printf("udp len:%d\n", udp->len);
		/* define/compute tcp payload (segment) offset */
		int size_ip = sizeof(struct ip);
		int size_udp = sizeof(struct udphdr);
		u_char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

		/* compute tcp payload (segment) size */
		int size_payload = ntohs(ip-> tot_len) - (size_ip + size_udp);

		/*
		 * Print payload data; it might be binary, so don't just
		 * treat it as a string.
		 */
		if (size_payload > 0) {
			printf("   Payload (%d bytes):\n", size_payload);
			print_payload(payload, size_payload);
		}
	}

	//printf("fin:%x,syn:%x,rst:%x,psh:%x,ack:%x,urg:%x\n", udp->fin,udp->syn,udp->rst,udp->psh,udp->ack,udp->urg );

	addr.sin_family = AF_INET;
	addr.sin_port = DESTPORT;
	addr.sin_addr.s_addr = inet_addr(DEST);
	ip->daddr = addr.sin_addr.s_addr;
	ip->saddr = inet_addr(srcbuf);
	ip->check = 0;
	ip->check = check_sum((unsigned short *)ip,sizeof(struct iphdr));
	//udp->source = htons(8443);
	udp->dest = addr.sin_port;
	udp->check = 0;
	psdhdr.saddr = ip->saddr;
	psdhdr.daddr = ip->daddr;
	psdhdr.mbz = 0;
	psdhdr.ptcl = IPPROTO_UDP;
	psdhdr.tcpl = htons(ip_len - sizeof(struct iphdr));
	memcpy(temp,&psdhdr,sizeof(struct psd_header));
	memcpy(temp + sizeof(struct psd_header), udp,ip_len - sizeof(struct iphdr));
	udp->check = check_sum((unsigned short *)temp,sizeof(struct psd_header) + ip_len - sizeof(struct iphdr));
	int ret = sendto(sockfd,buffer + sizeof(struct ethhdr),ip_len,0,(struct sockaddr *)(&addr),sizeof(struct sockaddr));
	if (ret == -1) {
		printf("sendto get error %d %s\n", errno, strerror(errno));
	}
	monitor_current++;
	//printf("%s\n", srcbuf);
}

unsigned short check_sum(unsigned short *addr,int len){
	register int nleft = len;
	register int sum = 0;
	register u_short *w = addr;
	u_short answer = 0;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}
	if(nleft == 1){
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

int main(int argc, char **argv)
{

	setbuf(stdout, NULL);
	char *dev = NULL;   /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
	pcap_t *handle;    /* packet capture handle */

	char filter_exp[] = FILTER_EXP;  /* filter expression [3] */
	struct bpf_program fp;   /* compiled filter program (expression) */
	bpf_u_int32 mask;   /* subnet mask */
	bpf_u_int32 net;   /* ip */
	int num_packets = -1;   /* number of packets to capture */
	debug = 1;

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];

	}else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
					errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);
	printf("haah\n");

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	//pcap_loop(handle, num_packets, got_packet, NULL);
	int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);  
	if(sockfd < 0){  
		fprintf(stderr,"Socket error:\n");  
		exit(-4);  
	}  
	int on = 1; 
	if(setsockopt(sockfd, IPPROTO_IP,IP_HDRINCL,&on,sizeof(on)) < 0)  
		fprintf(stderr,"HDRINCL error\n");  
	monitor_current = 0;
	monitor_total = 0;
	start_monitor(10);
	pcap_loop(handle, num_packets, handle_packet, (u_char *)&sockfd);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}

