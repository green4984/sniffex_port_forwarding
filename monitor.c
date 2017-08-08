#include "monitor.h"
#include <pthread.h>


void start_monitor_thread(void *timeout)
{
	extern int monitor_total;
	extern int monitor_current;
	int t = *(int *)timeout;
	printf("start monitor ...\n");
	while(1) {
		sleep(t);
		printf("transmission speed: %d pps \ttotal count: %d\n", monitor_current - monitor_total, monitor_total);
		monitor_total = monitor_current;
	}
}

void start_monitor(int timeout)
{
	pthread_t tid;
	pthread_create(&tid, NULL, (void *)start_monitor_thread, (void *)&timeout);
	sleep(1);
}
