// #include <linux/ip.h>
// #include <linux/netfilter.h>

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

#include <arpa/inet.h>
#include "dns_utils.h" // 包含 extract_final_a_domain 和 query_txt_record 的声明
#include "txt_query.thread.h"

#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif

#ifndef NF_DROP
#define NF_DROP 0
#endif

#define NFQUEUE_NUM 6

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

// 新增全局链表头指针
struct pending_response_node *response_chain_head = NULL;

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
    struct pending_response *res = malloc(sizeof(struct pending_response));
    if (!res)
        return -1;

    strncpy(res->domain, domain, MAX_DOMAIN_LEN);
    res->id = id;
    res->original_payload = malloc(len);
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
    struct pending_response_node *new_node = malloc(sizeof(struct pending_response_node));
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

// NFQUEUE 回调
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    (void)nfmsg; // 明确 nfmsg 未被使用
    (void)data;  // 明确 data 未被使用

    int len = 0;
    uint32_t id = 0;
    unsigned char *payload = NULL;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph)
        goto out;

    id = ntohl(ph->packet_id);

    len = nfq_get_payload(nfa, &payload);
    if (len < 0)
        goto out;

    struct iphdr *iph = (struct iphdr *)payload;
    char src_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_addr, sizeof(src_addr));

    // 有时Linux主机上会配置127.0.0.53为默认的DNS服务器（实际是一个本地的代理），如果本地查不到会转发到系统配置的真实的DNS SERVER（譬如由DHCP SERVER返回的DNS SERVER）
    // 这种情况会导致同一个A记录响应报文产生2次触发（一次是报文从DNS服务器抵达物理网卡，另一次是报文从本地代理抵达127.0.0.1）并引发混乱
    // 为了简化流程，我们只处理系统配置的默认的DNS SERVER的响应
    bool is_dns_server = false;
    for (int i = 0; i < MAX_DNS_SERVERS && g_dns_servers[i]; i++)
    {
        if (strcmp(src_addr, g_dns_servers[i]) == 0)
        {
            is_dns_server = true;
            break;
        }
    }
    if (!is_dns_server)
    {
        printf("Packet from non-system-default DNS server: %s, let pass\n", src_addr);
        goto out;
    }

    if (iph->protocol != IPPROTO_UDP)
        goto out;

    struct udphdr *udph = (struct udphdr *)(payload + iph->ihl * 4);
    if (ntohs(udph->source) != 53)
        goto out;

    unsigned char *dns_payload = payload + iph->ihl * 4 + sizeof(struct udphdr);
    int dns_len = len - (dns_payload - payload);

    char domain[MAX_DOMAIN_LEN];
    if (is_a_record_response(dns_payload, dns_len, domain))
    {
        printf("Received A record response for domain: %s, id: %d, len: %d\n", domain, id, len);
        enqueue_txt_query(domain);
        printf("Enqueued TXT query for domain: %s\n", domain);
        insert_pending_response(domain, id, payload, len);
        printf("Inserted pending response for domain: %s\n", domain);
        printf("------\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    int version = 0;
    if (is_txt_record_response(dns_payload, dns_len, &version, domain))
    {
        if (version > 0)
        {
            printf("Host %s support DART Version: %d\n", domain, version);
        }

        struct pending_response *res = pickup_response(domain);

        if (res)
        {
            printf("Picked up original A record domain: %s, id: %d, length: %d\n", res->domain, res->id, res->original_len);
            printf("\033[32m");
            printf("Sending verdict for original A record ... id: %d, len: %d\n", res->id, res->original_len);
            printf("\033[0m");
            int ret = nfq_set_verdict(qh, id, NF_ACCEPT, res->original_len, res->original_payload);

            free(res->original_payload);
            free(res);

            if (ret < 0)
                perror("nfq_set_verdict");
            else
                printf("Verdict sent successfully.\n");
            printf("------\n");

            return ret;
        }

        printf("No pending response found for domain: %s, let pass\n", domain);
    }

out:
    printf("Sending verdict for unprocessed packet ... id: %d, len: %d\n", id, len);
    // hex_dump("Unprocessed packet", payload, len);
    printf("------\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
}

int main()
{
    init_dns_servers();
    printf("DNS servers: \n");
    for (int i = 0; i < g_dns_server_count; i++)
    {
        printf("%s\n", g_dns_servers[i]);
    }

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

    // 创建一个队列，队列号改为 100
    struct nfq_q_handle *qh = nfq_create_queue(h, NFQUEUE_NUM, &cb, NULL);
    if (!qh)
    {
        perror("nfq_create_queue");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("nfq_set_mode");
        exit(1);
    }

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

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
