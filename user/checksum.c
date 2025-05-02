#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>  // struct iphdr
#include <netinet/udp.h> // struct udphdr
#include <netinet/tcp.h> // struct tcphdr
#include <arpa/inet.h>   // htons, ntohs

#pragma pack(1)

// 新增：提取出的公共函数，用于按16位进行反码求和
static uint32_t compute_checksum16(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    const uint8_t *ptr = data;

    // 处理完整的16位块
    while (len >= 2) {
        sum += ptr[0]<<8 | ptr[1];
        ptr += 2;
        len -= 2;
    }

    // 处理奇数字节
    if (len > 0) {
        sum += ptr[0] << 8;
    }

    // 处理进位
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16); // 再次处理可能的进位

    return sum;
}

void fix_udp_checksum(uint8_t *ip_packet)
{
    struct iphdr *iph = (struct iphdr *)ip_packet;
    if (iph->protocol != IPPROTO_UDP)
        return;

    int ip_header_len = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *)(ip_packet + ip_header_len);
    int udp_len = ntohs(udph->len);

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
    sum = compute_checksum16((const uint8_t *)&pseudo_header, sizeof(pseudo_header));

    // UDP头和数据的校验和
    sum += compute_checksum16((const uint8_t *)udph, udp_len);

    // 处理进位
    sum = (sum >> 16) + (sum & 0xFFFF);

    // 取反并处理零值情况
    uint16_t checksum = ~((uint16_t)sum);
    udph->check = (checksum == 0) ? 0xFFFF : htons(checksum);
}

void fix_tcp_checksum(uint8_t *ip_packet)
{
    struct iphdr *iph = (struct iphdr *)ip_packet;
    if (iph->protocol != IPPROTO_TCP)
        return;

    int ip_header_len = iph->ihl * 4;
    int ip_pkt_len = ntohs(iph->tot_len);

    struct tcphdr *tcph = (struct tcphdr *)(ip_packet + ip_header_len);
    // int tcp_len = ntohs(tcph->doff) * 4;
    int tcp_len = ip_pkt_len - ip_header_len;

    // 构造伪首部
    struct
    {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header = {
        .src_addr = iph->saddr,
        .dst_addr = iph->daddr,
        .zero = 0,
        .protocol = IPPROTO_TCP,
        .tcp_length = htons(tcp_len)};

    // 清零校验和
    tcph->check = 0;

    // 计算校验和
    uint32_t sum = 0;

    // 伪首部的校验和
    sum = compute_checksum16((const uint8_t *)&pseudo_header, sizeof(pseudo_header));

    // TCP头和数据的校验和
    sum += compute_checksum16((const uint8_t *)tcph, tcp_len);

    // 处理进位
    sum = (sum >> 16) + (sum & 0xFFFF);

    // 取反并处理零值情况
    uint16_t checksum = ~((uint16_t)sum);
    tcph->check = (checksum == 0) ? 0xFFFF : htons(checksum);
}

void fix_ip_checksum(uint8_t *ip_packet)
{
    struct iphdr *iph = (struct iphdr *)ip_packet;
    int ip_header_len = iph->ihl * 4;    

    // Step 1: 将校验和字段清零
    iph->check = 0;

    // Step 2: 使用公共函数计算校验和
    uint32_t sum = compute_checksum16(ip_packet, ip_header_len);

    // Step 3: 取反并写入校验和字段
    uint16_t checksum = ~(uint16_t)sum;

    iph->check = htons(checksum);
}