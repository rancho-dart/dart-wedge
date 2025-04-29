#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>   // for htons, ntohs
#include <netinet/ip.h>  // struct iphdr
#include <netinet/udp.h> // struct udphdr

static uint16_t checksum16(uint8_t *data, int len)
{
    uint32_t sum = 0;
    // const uint8_t* ptr = (const uint8_t*)data;
    // while (len > 1) {
    //     uint16_t word = (ptr[0] << 8) | ptr[1];
    //     printf("%04x %04x | ", *(const uint16_t *)ptr, word);
    //     sum += word;
    //     ptr += 2;
    //     len -= 2;
    // }
    // if (len > 0) {
    //     uint16_t word = ptr[0] << 8;
    //     sum += word;
    // }
    uint16_t word;
    for (size_t i = 0; i < len; i += 2)
    {
        if (i + 1 < len)
        {
            word = (data[i] << 8) | data[i + 1]; // 大端序组合
        }
        else
        {
            word = (data[i] << 8); // 奇数长度补零
        }
        sum += word;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(sum); // 因为UDP的Checksum是两个Checksum的叠加，因此这里不取反
}

void fix_udp_checksum(uint8_t *ip_packet, size_t ip_packet_len)
{
    struct iphdr *iph = (struct iphdr *)ip_packet;
    if (iph->protocol != IPPROTO_UDP)
        return;

    int ip_header_len = iph->ihl * 4;
    if (ip_packet_len < ip_header_len + sizeof(struct udphdr))
        return; // 长度检查

    struct udphdr *udph = (struct udphdr *)(ip_packet + ip_header_len);
    int udp_len = ntohs(udph->len);

    if (udp_len < sizeof(struct udphdr) ||
        ip_header_len + udp_len > ip_packet_len)
        return; // 长度检查

    // 构造伪首部
    struct
    {
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
        .udp_length = htons(udp_len)};

    // 清零校验和
    udph->check = 0;

    // 计算校验和
    uint32_t sum = 0;

    // 伪首部的校验和
    sum = checksum16((uint8_t *)&pseudo_header, sizeof(pseudo_header));

    // UDP头和数据的校验和
    sum += checksum16((uint8_t *)udph, udp_len);

    // 处理进位
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // 取反并处理零值情况
    uint16_t checksum = (uint16_t)(~sum);
    udph->check = (checksum == 0) ? 0xFFFF : htons(checksum);
}

void fix_ip_checksum(uint8_t *ip_packet, size_t ip_packet_len)
{
    // Step 1: 将校验和字段清零
    ip_packet[10] = 0;
    ip_packet[11] = 0;

    uint32_t sum = 0;
    uint16_t word;

    // Step 2: 按16位字进行反码求和
    for (size_t i = 0; i < ip_packet_len; i += 2)
    {
        if (i + 1 < ip_packet_len)
        {
            word = (ip_packet[i] << 8) | ip_packet[i + 1]; // 大端序组合
        }
        else
        {
            word = (ip_packet[i] << 8); // 奇数长度补零
        }
        sum += word;
    }

    // Step 3: 处理进位
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Step 4: 取反并写入校验和字段
    uint16_t checksum = ~(uint16_t)sum;
    ip_packet[10] = (checksum >> 8) & 0xff; // 大端序写入
    ip_packet[11] = checksum & 0xff;
}