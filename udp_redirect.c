#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
	if (argc!=3 && argc!=5) {
		printf("Usage: %s our-ip our-port send-to-ip send-to-port\n",argv[0]);
		printf("Usage: %s our-ip our-port             # echo mode\n",argv[0]);
		exit(1);
	}

	int os=socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);

	struct sockaddr_in a;
	a.sin_family=AF_INET;
	a.sin_addr.s_addr=inet_addr(argv[1]); a.sin_port=htons(atoi(argv[2]));
	if(bind(os,(struct sockaddr *)&a,sizeof(a)) == -1) {
		printf("Can't bind our address (%s:%s)\n", argv[1], argv[2]);
		exit(1); }

	if(argc==5) { a.sin_addr.s_addr=inet_addr(argv[3]); a.sin_port=htons(atoi(argv[4])); }

	struct sockaddr_in sa;
	struct sockaddr_in da; da.sin_addr.s_addr=0;
	while(1) {
		char buf[65535];
		int sn=sizeof(sa);
		int n=recvfrom(os,buf,sizeof(buf),0,(struct sockaddr *)&sa,&sn);
		if(n<=0) continue;

		if(argc==3) { sendto(os,buf,n,0,(struct sockaddr *)&sa,sn);
		} else if(sa.sin_addr.s_addr==a.sin_addr.s_addr && sa.sin_port==a.sin_port) {
			if(da.sin_addr.s_addr) sendto(os,buf,n,0,(struct sockaddr *)&da,sizeof(da));
		} else {
			sendto(os,buf,n,0,(struct sockaddr *)&a,sizeof(a));
			da=sa;
		}
	}
}
