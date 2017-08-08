#ifndef UTILS_H
#define UTILS_H

#include "sniffex.h"

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *, int, int);

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len);
unsigned short check_sum(unsigned short *addr,int len);
#endif
