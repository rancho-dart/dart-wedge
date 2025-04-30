#ifndef CHECKSUM_H
#define CHECKSUM_H 

#include <stdint.h>
#include <stddef.h>
// 注意：TCP/UDP报文的Checksum计算需要包括伪头部（其中包含IP报头内容），所以需要先把IP报头装配完成后再调用这里的函数
void fix_ip_checksum(uint8_t* ip_packet);
void fix_tcp_checksum(uint8_t* ip_packet);
void fix_udp_checksum(uint8_t* ip_packet);

#endif