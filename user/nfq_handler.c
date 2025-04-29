// #include <linux/ip.h>
// #include <linux/netfilter.h>
#define _POSIX_C_SOURCE 200112L // 或者 #define _XOPEN_SOURCE 600
#include <netdb.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include "dns_utils.h" // 包含 extract_final_a_domain 和 query_txt_record 的声明
#include "txt_query.thread.h"
// #include "pseudo_ip_c_api.h"
#include "checksum.h"
#include "dart.h"
#include "pseudo_ip_capi.h"

#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif

#ifndef NF_DROP
#define NF_DROP 0
#endif

#define NFQUEUE_INBOUND_DNS_NO 100
#define NFQUEUE_OUTBOUND_IP_NO 101

// key: DNS response id or domain
// value: 包含原始A记录报文，状态、时间戳等
struct pending_response
{
    char domain[MAX_DOMAIN_LEN];
    uint32_t id;
    unsigned char *original_payload;
    int original_len;
    bool txt_sent;
    bool txt_received;
};

// 新增链表节点结构
struct pending_response_node
{
    struct pending_response *response;
    struct pending_response_node *next;
};

char localhost_fqdn[256];

// 新增全局链表头指针
struct pending_response_node *response_chain_head = NULL;

char * ip_to_str(uint32_t ip)
{
    static char ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
    return ip_str;
}

int modify_a_record_ip(unsigned char *dns_payload, int dns_len, const char *new_ip)
{
    // 假设我们要修改的 A 记录在 dns_payload 中
    // 这里需要解析 DNS 消息并找到 A 记录的位置
    // 然后将其替换为 new_ip

    (void)dns_payload; // 明确 dns_payload 未被使用
    (void)dns_len;     // 明确 dns_len 未被使用
    (void)new_ip;      // 明确 new_ip 未被使用
    // 具体实现略
    return 0;
}

int insert_pending_response(const char *domain, uint32_t id, unsigned char *payload, int len)
{
    // printf("Inserting pending response for domain: %s, id: %d, length: %d\n", domain, id, len);
    // hex_dump("Original payload", payload, len);

    // 插入待处理请求
    struct pending_response *res = (struct pending_response *)malloc(sizeof(struct pending_response));
    if (!res)
        return -1;

    strncpy(res->domain, domain, MAX_DOMAIN_LEN);
    res->id = id;
    res->original_payload = (unsigned char *)malloc(len);
    if (!res->original_payload)
    {
        free(res);
        return -1;
    }
    memcpy(res->original_payload, payload, len);
    res->original_len = len;
    res->txt_sent = false;
    res->txt_received = false;

    // 将 req 插入到链表头部
    struct pending_response_node *new_node = (struct pending_response_node *)malloc(sizeof(struct pending_response_node));
    if (!new_node)
    {
        free(res->original_payload);
        free(res);
        return -1;
    }
    new_node->response = res;
    new_node->next = response_chain_head;
    response_chain_head = new_node;

    return 0;
}

struct pending_response *pickup_response(const char *domain)
{
    // 从数据结构中查找 domain 对应的请求
    struct pending_response_node *current = response_chain_head;
    struct pending_response_node *prev = NULL;

    while (current)
    {
        if (strcmp(current->response->domain, domain) == 0)
        {
            // 找到匹配节点，将其从链表中摘除
            if (prev)
            {
                prev->next = current->next; // 更新前一个节点的 next 指针
            }
            else
            {
                response_chain_head = current->next; // 如果是头节点，更新链表头
            }

            // 保存当前节点的响应数据
            struct pending_response *response = current->response;

            // 释放当前节点的内存，但不释放 response 内存
            free(current);

            // 返回被移除的响应数据
            return response;
        }

        prev = current;
        current = current->next;
    }

    return NULL; // 未找到匹配节点
}

int remove_response(const char *domain)
{
    struct pending_response_node *current = response_chain_head;
    struct pending_response_node *prev = NULL;

    // 遍历链表寻找匹配的节点
    while (current)
    {
        if (strcmp(current->response->domain, domain) == 0)
        {
            // 找到匹配节点，释放内存
            if (prev)
            {
                prev->next = current->next; // 更新前一个节点的 next 指针
            }
            else
            {
                response_chain_head = current->next; // 如果是头节点，更新链表头
            }

            // 释放 pending_response 结构体的内存
            free(current->response->original_payload);
            free(current->response);
            free(current);

            return 0; // 成功移除
        }

        prev = current;
        current = current->next;
    }

    return -1; // 未找到匹配节点
}

// 新增辅助函数：释放链表资源
void free_pending_response()
{
    struct pending_response_node *current = response_chain_head;
    while (current)
    {
        struct pending_response_node *temp = current;
        current = current->next;
        free(temp->response->original_payload);
        free(temp->response);
        free(temp);
    }
    response_chain_head = NULL;
}

bool is_dns_server(char *src_addr)
{
    for (int i = 0; i < MAX_DNS_SERVERS && g_dns_servers[i]; i++)
        if (strcmp(src_addr, g_dns_servers[i]) == 0)
            return true;

    return false;
}

// NFQUEUE 回调
static int cb_inbound_dns(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    (void)nfmsg;
    (void)data;

    int len = 0;
    uint32_t id = 0;
    unsigned char *payload = NULL;
    bool support_dart = false;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph)
    {
        printf("Invalid packet header, letting the packet pass.\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    id = ntohl(ph->packet_id);
    len = nfq_get_payload(nfa, &payload);
    if (len < 0)
    {
        printf("Failed to get payload, letting the packet pass.\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    struct iphdr *iph = (struct iphdr *)payload;
    char src_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_addr, sizeof(src_addr));

    if (!is_dns_server(src_addr))
    {
        printf("Packet from non-system-default DNS server: %s, letting it pass.\n", src_addr);
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }
    struct udphdr *udph = (struct udphdr *)(payload + iph->ihl * 4);

    unsigned char *dns_pkt = payload + iph->ihl * 4 + sizeof(struct udphdr);
    int dns_pkt_len = len - (dns_pkt - payload);

    char domain[MAX_DOMAIN_LEN] = {0};
    char cname[MAX_DOMAIN_LEN] = {0};
    struct in_addr ip;
    struct in_addr pseudo_ip_addr;
    int a_record_pos = -1;
    int ret = follow_cname_chain(dns_pkt, len, domain, cname, &ip, &a_record_pos);
    printf("Followed CNAME chain for domain: %s, cname: %s, ip: %s\n", domain, cname, inet_ntoa(ip));
    if (ret < 0)
    {
        printf("Failed to follow CNAME chain, letting the packet pass.\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    if (strncmp(cname, "dart-host.", 10) == 0 || strncmp(cname, "dart-gateway.", 13) == 0)
    {
        printf("Host %s supports DART\n", domain);

        const PseudoIPEntryC* entry = pseudo_ip_allocator_allocate(domain, ip.s_addr);

        if (entry == NULL)
        {
            printf("Failed to allocate pseudo IP for %s\n", domain);
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
        }

        pseudo_ip_addr.s_addr = entry->pseudo_ip;
        char *pseudo_ip_str = strdup(inet_ntoa(pseudo_ip_addr));
        char *ip_str = strdup(inet_ntoa(ip));
        printf("Replace real IP %s with pseudo IP %s\n", ip_str, pseudo_ip_str);
        free(ip_str);
        free(pseudo_ip_str);

        // replace real IP with pseudo IP, the position is a_record_pos
        int *ip_ptr = (int *)(dns_pkt + a_record_pos);
        memcpy(ip_ptr, &pseudo_ip_addr.s_addr, sizeof(pseudo_ip_addr.s_addr));

        // 因为没有改IP报头，IP的Checksum不需要更新

        // UDP报头中的Checksum是包含负载一起计算的，所以需要更新。但是可以置0忽略。
        udph->check = 0;  // 先清零
        // fix_udp_checksum(payload, len);

        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }
    else
    {
        // Host does not support DART, let it pass
    }

    printf("Sending verdict for unprocessed packet ... id: %d, len: %d\n", id, len);
    return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
}

int insert_dart_headers(unsigned char *orig_pkt, int orig_len, nbo_ipv4_t dest_ip, const char *dest_fqdn, const char *src_fqdn,
                        unsigned char *new_pkt, int *new_len)
{
    // 根据我们的设计，DART协议将由2层组成：
    // 1.  UDP头
    // 因为网络上充斥着各种NAT网关，IP层的协议只有有限的几种（TCP/UDP/ICMP）等可以通过，
    // 自定义的协议无法通过，所以设计使用UDP协议在确保DART报文可以通过NAT网关。
    // 2.  Dart头
    // struct dart_header
    // {
    //     uint8_t version;
    //     uint8_t proto;
    //     uint8_t daddr_len;
    //     uint8_t saddr_len;
    //     char daddr[];
    //     char saddr[];
    // }
    // 其中，daddr和saddr是可变长度的字段，分别表示目标地址和源地址。

    struct iphdr *ip_header = (struct iphdr *)orig_pkt;
    unsigned char *ip_payload = orig_pkt + ip_header->ihl * 4;
    int ip_payload_len = orig_len - (ip_header->ihl * 4);

    int dart_header_len = 4 + strlen(dest_fqdn) + strlen(src_fqdn);

    *new_len = orig_len + sizeof(struct udphdr) + dart_header_len;
    memcpy(new_pkt, orig_pkt, ip_header->ihl * 4);
    struct iphdr *ip_header_for_dart = (struct iphdr *)new_pkt;
    ip_header_for_dart->tot_len  = htons(*new_len);
    ip_header_for_dart->protocol = IPPROTO_UDP;
    ip_header_for_dart->daddr = dest_ip;
    fix_ip_checksum(new_pkt, *new_len);        

    struct udphdr *udp_header_for_dart = (struct udphdr *)(new_pkt + ip_header->ihl * 4);
    udp_header_for_dart->source = htons(DART_PORT);
    udp_header_for_dart->dest = htons(DART_PORT);
    udp_header_for_dart->len = htons(*new_len - ip_header->ihl * 4);
    udp_header_for_dart->check = 0;

    struct dart_header *dart_header = (struct dart_header *)(udp_header_for_dart + 1);
    dart_header->version = DART_VERSION;
    dart_header->proto = ip_header->protocol;
    dart_header->daddr_len = strlen(dest_fqdn);
    dart_header->saddr_len = strlen(src_fqdn);

    unsigned char *dart_header_dest = (unsigned char *)(dart_header + 1);
    memcpy(dart_header_dest, dest_fqdn, strlen(dest_fqdn));
    unsigned char *dart_header_src = dart_header_dest + dart_header->daddr_len;
    memcpy(dart_header_src, src_fqdn, strlen(src_fqdn));

    fix_ip_checksum(new_pkt, *new_len); // IP校验和与报文总长有关吗？如果无关，放前面去

    void *dart_payload = dart_header_src + dart_header->saddr_len;
    memcpy(dart_payload, ip_payload, ip_payload_len);

    fix_udp_checksum(new_pkt, *new_len);  // 因为UDP校验和包含整个报文的内容，所以要在全部数据设置完成后计算

    return 0;
}

static int cb_outbound_ip(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int len = 0;
    uint32_t id = 0;
    unsigned char *payload = NULL;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph)
    {
        printf("Invalid packet header, letting the packet pass.\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    id = ntohl(ph->packet_id);
    len = nfq_get_payload(nfa, &payload);

    if (len < 0)
    {
        printf("Failed to get payload, letting the packet pass.\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    struct iphdr *ip_header = (struct iphdr *)payload;
    if (ip_header->version != 4)
    {
        printf("Invalid IP version, letting the packet pass.\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload); // 非IPv4放行
    }
    // printf("Received packet from %s\n", ip_to_str(ip_header->saddr));

    if (ip_header->protocol != IPPROTO_UDP && ip_header->protocol != IPPROTO_TCP && ip_header->protocol != IPPROTO_ICMP)
    {
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    // If is dns or dhcp packet, 放行
    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)(payload + ip_header->ihl * 4);
        if (udp_header->dest == htons(DNS_PORT) || udp_header->dest == htons(DHCP_PORT))
        {
            printf("Received DNS or DHCP packet, pass it\n");
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
        }
    }

    printf("Received packet from %s\n", ip_to_str(ip_header->saddr));

    if (!is_pseudo_ip(ip_header->daddr))
    {
        // 如果不是发往伪IP，则直接放行
        printf("Not a pseudo IP packet(%s), pass it\n", ip_to_str(ip_header->daddr));
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }
    
    const PseudoIPEntryC* entry = pseudo_ip_allocator_find_by_pseudo_ip(ip_header->daddr);
    if (entry == NULL)
    {
        printf("Failed to find pseudo IP entry for %s\n", ip_to_str(ip_header->daddr));
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    const char *dest_fqdn = entry->domain;
    const char *src_fqdn = localhost_fqdn;

    // 修改报文：插入UDP头和Dart头
    unsigned char modified_pkt[2048]; // MTU(1500) + DART(2*256 + 4) + UDP(8) = 2024 这是插入了Dart头后的报文最大长度
    int modified_pkt_len;
    if (insert_dart_headers(payload, len, entry->real_ip, dest_fqdn, src_fqdn, modified_pkt, &modified_pkt_len) != 0)
    {
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }

    // 放行修改后的报文
    printf("Original packet from %s, id: %d, length: %d\n", ip_to_str(ip_header->saddr), id, len);
    hex_dump("Packet:", payload, len);

    printf("Modified packet from %s, id: %d, length: %d\n", ip_to_str(ip_header->saddr), id, modified_pkt_len);
    hex_dump("Modified packet:", modified_pkt, modified_pkt_len);
    return nfq_set_verdict(qh, id, NF_ACCEPT, modified_pkt_len, modified_pkt);
}

int main()
{
    init_dns_servers();
    printf("DNS servers: \n");
    for (int i = 0; i < g_dns_server_count; i++)
    {
        printf("  %s\n", g_dns_servers[i]);
    }

    get_full_fqdn(localhost_fqdn);
    printf("Localhost FQDN: %s\n", localhost_fqdn);

    pthread_t worker_thread;
    pthread_create(&worker_thread, NULL, txt_query_worker, NULL);
    pthread_detach(worker_thread); // 设置为分离线程，主线程退出时，子线程也会退出

    struct nfq_handle *h = nfq_open(); // 创建一个 netfilter queue
    if (!h)
    {
        perror("nfq_open");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) // 解绑 pf
    {
        perror("nfq_unbind_pf");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) // 绑定 pf
    {
        perror("nfq_bind_pf");
        exit(1);
    }

    // 为入站的DNS报文创建队列
    struct nfq_q_handle *qh_inbound_dns = nfq_create_queue(h, NFQUEUE_INBOUND_DNS_NO, &cb_inbound_dns, NULL);
    if (!qh_inbound_dns)
    {
        perror("nfq_create_queue");
        exit(1);
    }

    if (nfq_set_mode(qh_inbound_dns, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("nfq_set_mode");
        exit(1);
    }
    printf("Listening on queue %d for inbound DNS packets...\n", NFQUEUE_INBOUND_DNS_NO);

    // 为出站的IP报文创建队列
    struct nfq_q_handle *qh_outbound_ip = nfq_create_queue(h, NFQUEUE_OUTBOUND_IP_NO, &cb_outbound_ip, NULL);
    if (!qh_outbound_ip)
    {
        perror("nfq_create_queue");
        exit(1);
    }
    if (nfq_set_mode(qh_outbound_ip, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("nfq_set_mode");
        exit(1);
    }
    printf("Listening on queue %d for outbound IP packets...\n", NFQUEUE_OUTBOUND_IP_NO);

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    while (1)
    {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0)
        {
            nfq_handle_packet(h, buf, rv);
        }
        else if (rv < 0 && errno != ENOBUFS)
        {
            perror("recv failed");
            break;
        }
    }

    nfq_destroy_queue(qh_inbound_dns);
    nfq_close(h);
    return 0;
}
