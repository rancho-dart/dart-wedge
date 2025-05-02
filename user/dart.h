#pragma once

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
#define DART_UDP_PORT 0xDA27 // 2 sounds like R, 7 looks like T
#define DART_MAX_NAME_LENGTH 256
#define MAX_DART_PKG_LEN (ETH_DATA_LEN + 2 * DART_MAX_NAME_LENGTH + 4 + 8)  // 4 is the fixed part of Dart header, 8 is the len of udp


struct dart_header
{
    uint8_t version;
    uint8_t proto;
    uint8_t daddr_len;
    uint8_t saddr_len;
    // char daddr[256];  // 这两个变量因为是变长的，因此不适合在结构中定义
    // char saddr[256];
};

#define daddr_of_dart(dart_header) ((char *)((char *)(dart_header) + 4))
#define saddr_of_dart(dart_header) ((char *)((char *)(dart_header) + 4 + (dart_header)->daddr_len))


