#ifndef DART_H
#define DART_H
#include <stdint.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define DART_VERSION 1
#define DART_PORT 0xDA27 // 2 sounds like R, 7 looks like T

struct dart_header
{
    uint8_t version;
    uint8_t proto;
    uint8_t daddr_len;
    uint8_t saddr_len;
    // char daddr[256];  // 这两个变量因为是变长的，因此不适合在结构中定义
    // char saddr[256];
};
int serialize_udp_header(const struct iphdr *ip_header, uint8_t *udp_out);
void deserialize_udp_header(const uint8_t *buf, struct sockaddr_in *daddr, struct sockaddr_in *saddr);
int serialize_dart_header(const struct dart_header *h, uint8_t *buf);
void deserialize_dart_header(const uint8_t *buf, struct dart_header *h);

#endif