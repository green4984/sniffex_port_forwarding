all: sniffex.c utils.c monitor.c
	@#gcc -g test.c -o a.out -lpcap
	gcc -g -Wall -o sniffex $^ -lpcap -lpthread
