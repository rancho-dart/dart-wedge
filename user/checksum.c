#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>  // for htons, ntohs
#include <netinet/ip.h> // struct iphdr
#include <netinet/udp.h> // struct udphdr

static uint16_t checksum16(const void* data, int len) {
    uint32_t sum = 0;
    const uint16_t* ptr = (const uint16_t*)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) {
        sum += *((const uint8_t*)ptr);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// 自动处理IP报文，重新计算并设置UDP校验和
void fix_udp_checksum(uint8_t* ip_packet, size_t ip_packet_len) {
    struct iphdr* iph = (struct iphdr*)ip_packet;
    if (iph->protocol != IPPROTO_UDP) return;

    int ip_header_len = iph->ihl * 4;
    struct udphdr* udph = (struct udphdr*)(ip_packet + ip_header_len);
    int udp_len = ntohs(udph->len);

    // 构造伪首部
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } pseudo_header = {
        .src_addr = iph->saddr,
        .dst_addr = iph->daddr,
        .zero = 0,
        .protocol = IPPROTO_UDP,
        .udp_length = htons(udp_len) // 显式转换
    };

    // 清零校验和
    udph->check = 0;

    // 合并伪首部和UDP报文
    uint8_t* buffer = (uint8_t*)malloc(sizeof(pseudo_header) + udp_len);
    memcpy(buffer, &pseudo_header, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), udph, udp_len);

    // 计算校验和
    uint32_t sum = checksum16(buffer, sizeof(pseudo_header) + udp_len);
    free(buffer);

    // 处理奇数字节填充
    if (udp_len % 2 != 0) {
        uint8_t padding = 0; // 定义显式的填充字节
        sum += checksum16(&padding, 1); // 传递显式变量的地址
    }

    // 最终取反
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    udph->check = htonl((uint16_t)(~sum));
}

void fix_ip_checksum(uint8_t *ip_packet, size_t ip_packet_len) {
    // Step 1: 将校验和字段清零
    ip_packet[10] = 0;
    ip_packet[11] = 0;

    uint32_t sum = 0;
    uint16_t word;

    // Step 2: 按16位字进行反码求和
    for (size_t i = 0; i < ip_packet_len; i += 2) {
        if (i + 1 < ip_packet_len) {
            word = (ip_packet[i] << 8) | ip_packet[i + 1]; // 大端序组合
        } else {
            word = (ip_packet[i] << 8); // 奇数长度补零
        }
        sum += word;
    }

    // Step 3: 处理进位
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Step 4: 取反并写入校验和字段
    uint16_t checksum = ~(uint16_t)sum;
    ip_packet[10] = (checksum >> 8) & 0xff; // 大端序写入
    ip_packet[11] = checksum & 0xff;
}
