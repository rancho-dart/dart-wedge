#ifndef CHECKSUM_H
#define CHECKSUM_H 

#include <stdint.h>
#include <stddef.h>

void fix_udp_checksum(uint8_t* ip_packet, size_t ip_packet_len);
void fix_ip_checksum(uint8_t* ip_packet, size_t ip_packet_len);

#endif