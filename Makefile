all:
	@#gcc -g test.c -o a.out -lpcap
	gcc -g -Wall -o sniffex sniffex.c -lpcap
