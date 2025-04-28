#include <regex.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "dns_utils.h"

bool traversing_question_sec(const unsigned char *payload, size_t len, const unsigned char **ptr, char *domain_out)
{
    const unsigned char *end = payload + len;

    if (len < sizeof(HEADER))
        return false;

    HEADER *dns = (HEADER *)payload;
    int qdcount = ntohs(dns->qdcount);

    // 跳过 question 区域
    for (int i = 0; i < qdcount; i++)
    {
        char tmp[MAX_DOMAIN_LEN];
        int n = dn_expand(payload, end, *ptr, tmp, sizeof(tmp));
        if (n < 0)
            return false;
        if (i == 0)
            strcpy(domain_out, tmp);

        *ptr += n + 4; // 跳过 QTYPE 和 QCLASS
        // 让for循环执行完，跳过剩余所有的Question（虽然通常只有1个）
    }
    return true;
}
// 修改后的 follow_cname_chain 函数，从 DNS ANSWER 报文中追踪 CNAME 链，返回最终的 A 记录中的域名和 IP
int follow_cname_chain(const unsigned char *dns_pkt, int len, char *domain_out, char *cname_out, struct in_addr *ip_out, int *a_record_pos)
{
    const unsigned char *end = dns_pkt + len;
    const unsigned char *ptr = dns_pkt + sizeof(HEADER);

    if (len < sizeof(HEADER))
        return -1;
    //
    HEADER *dns = (HEADER *)dns_pkt;
    int qdcount = ntohs(dns->qdcount);
    int ancount = ntohs(dns->ancount);

    char domain[MAX_DOMAIN_LEN];
    // hex_dump("DNS packet", dns_pkt, len);
    traversing_question_sec(dns_pkt, len, &ptr, domain); // 遍历DNS报文的Question区域，返回查询的domain，同时将ptr移动到下一个区域

    // 处理 answer 区域
    char cname_chain_node[MAX_DOMAIN_LEN];
    strcpy(cname_chain_node, domain); // cname chain begins from domain

    for (int i = 0; i < ancount && ptr < end; i++)
    {
        char name[MAX_DOMAIN_LEN];
        int n = dn_expand(dns_pkt, end, ptr, name, sizeof(name));
        if (n < 0)
            break;

        ptr += n;

        if (ptr + 10 > end)
            break;

        uint16_t type = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        uint32_t ttl = ntohl(*(uint32_t *)ptr);
        ptr += 4;
        uint16_t rdlength = ntohs(*(uint16_t *)ptr);
        ptr += 2;

        if (ptr + rdlength > end)
            break;

        if (type == T_CNAME)
        {
            // 跟踪 CNAME 指向的新域名
            char cname[MAX_DOMAIN_LEN];
            if (dn_expand(dns_pkt, end, ptr, cname, sizeof(cname)) >= 0)
            {
                if (strcmp(cname_chain_node, name) == 0) // if equal, replace chain node to new cname, to follow the chain
                    strcpy(cname_chain_node, cname);
                ptr += rdlength;
                continue;
            }
        }
        else if (type == T_A)
        {
            // 找到 A 记录，返回当前域名和 IP 地址
            if (strcmp(cname_chain_node, name) == 0)
            {
                strcpy(domain_out, domain);
                if (strcmp(domain, name) != 0)  // A record is provided by none-original domain (domain -> cname -> A)
                    strcpy(cname_out, name);
                else                            // A record is provided by original domain (domain -> A)
                    strcpy(cname_out, "");
                memcpy(ip_out, ptr, sizeof(*ip_out));
                *a_record_pos = ptr - dns_pkt; // 记录 A 记录的位置
                break;
            }
        }

        ptr += rdlength;
    }

    return 0;
}

void hex_dump(const char *msg, const unsigned char *data, size_t len)
{
    printf("%s Hex Dump:\n", msg);
    for (size_t i = 0; i < len; i += 16)
    {
        printf("%08zx  ", i); // 打印偏移地址
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < len)
            {
                printf("%02x ", data[i + j]); // 打印十六进制值
            }
            else
            {
                printf("   "); // 补齐空位
            }
        }
        printf(" ");
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < len)
            {
                unsigned char c = data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.'); // 打印可显示字符
            }
            else
            {
                printf(" "); // 补齐空位
            }
        }
        printf("\n");
    }
}

bool is_a_record_response(const unsigned char *dns_pkt, size_t len, char *domain)
{
    // hex_dump("DNS packet", dns_pkt, len);

    const HEADER *dns_hdr = (const HEADER *)dns_pkt;
    int qdcount = ntohs(dns_hdr->qdcount);
    int ancount = ntohs(dns_hdr->ancount);

    if (qdcount == 0 || ancount == 0)
        return false;

    const unsigned char *cur = dns_pkt + sizeof(HEADER);

    for (int i = 0; i < qdcount; i++)
    {
        char tmp[MAX_DOMAIN_LEN];
        int n = dn_expand(dns_pkt, dns_pkt + len, cur, tmp, sizeof(tmp));
        if (n < 0)
            return false;
        cur += n;
        cur += 4; // QTYPE + QCLASS

        if (i == 0)
        {
            // strncpy(domain, tmp, MAX_DOMAIN_LEN);
            // domain[MAX_DOMAIN_LEN - 1] = '\0';
            strcpy(domain, tmp); // tmp中的域名应当是0结尾的字符串
            // 到这里我们已经取得第一个问题区域的域名，但完成后并不退出循环，因为我们要移动cur指针直到跳过整个问题区域
        }
    }

    // 现在cur已经超过了Answer区域。如果存在Answer区域，cur现在实际指向answer区域的起始位置
    // 检查 answer 区域是否存在 A 记录
    for (int i = 0; i < ancount; i++)
    {
        // 解析域名并跳过
        char tmp[MAX_DOMAIN_LEN];
        int n = dn_expand(dns_pkt, dns_pkt + len, cur, tmp, sizeof(tmp));
        if (n < 0)
            return false;
        cur += n;

        if (cur + 10 > dns_pkt + len)
            return false;

        uint16_t type = ntohs(*(uint16_t *)cur);
        cur += 2;
        cur += 2; // CLASS
        cur += 4; // TTL
        uint16_t rdlength = ntohs(*(uint16_t *)cur);
        cur += 2;

        if (cur + rdlength > dns_pkt + len)
            return false;

        if (type == ns_t_a)
            return true;

        cur += rdlength;
    }

    return false;
}

bool is_txt_record_response(const unsigned char *dns_pkt, size_t len, int *version, char *domain)
{
    // hex_dump("DNS packet", dns_pkt, len);

    const HEADER *dns = (const HEADER *)dns_pkt;
    int qdcount = ntohs(dns->qdcount);
    int ancount = ntohs(dns->ancount);

    if (qdcount > 0 && ancount > 0)
    {
        const unsigned char *cur = dns_pkt + sizeof(HEADER);

        // 解析 question 区域并提取域名
        for (int i = 0; i < qdcount; i++)
        {
            char tmp[MAX_DOMAIN_LEN];
            int n = dn_expand(dns_pkt, dns_pkt + len, cur, tmp, sizeof(tmp));
            if (n < 0)
                return false;
            cur += n + 4; // 跳过 QTYPE 和 QCLASS

            // 将解析出的域名赋值给 domain 参数
            if (domain)
            {
                strncpy(domain, tmp, MAX_DOMAIN_LEN - 1);
                domain[MAX_DOMAIN_LEN - 1] = '\0'; // 确保字符串以 \0 结尾
            }
        }

        // 检查 answer 区域是否存在 TXT 记录
        for (int i = 0; i < ancount; i++)
        {
            // 解析域名并跳过
            char tmp[MAX_DOMAIN_LEN];
            int n = dn_expand(dns_pkt, dns_pkt + len, cur, tmp, sizeof(tmp));
            if (n < 0)
                return false;
            cur += n;

            if (cur + 10 > dns_pkt + len)
                return false;

            uint16_t type = ntohs(*(uint16_t *)cur);
            if (type == ns_t_txt)
            {
                // 跳过 TYPE 和 CLASS
                cur += 4;

                // 获取 TTL 和 RDLENGTH
                uint32_t ttl = ntohl(*(uint32_t *)cur);
                cur += 4;
                uint16_t rdlength = ntohs(*(uint16_t *)cur);
                cur += 2;

                // 解析 TXT 数据
                const unsigned char *txt_data = cur;
                if (rdlength > 0 && txt_data[0] == 0x07 && memcmp(txt_data + 1, "Dart:v", 6) == 0)
                {
                    // 找到 "Dart:v" 开头的 TXT 记录
                    *version = txt_data[7] - '0'; // 提取版本号
                    return true;                  // 是 TXT 记录响应
                }

                // 跳过当前记录
                cur += rdlength;
            }
            else
            {
                // 跳过其他类型的记录
                cur += 2; // 跳过 TYPE
                cur += 2; // 跳过 CLASS
                cur += 4; // 跳过 TTL
                uint16_t rdlength = ntohs(*(uint16_t *)cur);
                cur += 2;        // 跳过 RDLENGTH
                cur += rdlength; // 跳过 RDATA
            }
        }
    }
    *version = 0; // 未找到匹配的 TXT 记录
    return false; // 不是 TXT 记录响应
}

// 读取系统默认的 DNS 服务器
int get_system_dns_servers(char *dns_servers[], int max_servers)
{
    FILE *fp = fopen(DNS_CONF_PATH, "r");
    if (!fp)
    {
        perror("Failed to open /etc/resolv.conf");
        return 0; // 返回0表示没有找到任何DNS服务器
    }

    char line[256];
    int count = 0;

    while (fgets(line, sizeof(line), fp) && count < max_servers)
    {
        if (strncmp(line, "nameserver", 10) == 0)
        {
            char *addr = line + 10;
            while (*addr == ' ' || *addr == '\t')
                addr++;
            if (*addr)
            {
                // 删除换行符
                char *newline = strchr(addr, '\n');
                if (newline)
                    *newline = '\0';

                struct in_addr dummy;
                if (inet_pton(AF_INET, addr, &dummy) == 1)
                {
                    dns_servers[count++] = strdup(addr);
                }
            }
        }
    }

    fclose(fp);
    return count; // 返回找到的DNS服务器数量
}

// 新增全局变量：存储 DNS 服务器列表
char *g_dns_servers[MAX_DNS_SERVERS] = {0};
int g_dns_server_count = 0;

// 新增初始化函数：在程序启动时读取 DNS 服务器列表
bool init_dns_servers()
{
    if (g_dns_server_count > 0)
    {
        // 如果已经初始化过，直接返回成功
        return true;
    }
    int count = get_system_dns_servers(g_dns_servers, MAX_DNS_SERVERS);
    if (count <= 0)
    {
        fprintf(stderr, "Failed to initialize DNS servers\n");
        return false;
    }

    g_dns_server_count = count;

    return true;
}

int send_txt_query(const char *domain)
{
    const int dns_port = 53;

    // 确保 DNS 服务器列表已初始化
    if (!init_dns_servers())
    {
        fprintf(stderr, "No valid DNS servers found\n");
        return -1;
    }

    for (int i = 0; i < g_dns_server_count && g_dns_servers[i]; i++)
    {
        struct sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(dns_port);

        if (inet_pton(AF_INET, g_dns_servers[i], &server_addr.sin_addr) <= 0)
        {
            continue;
        }

        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            continue;
        }

        // 构造 DNS 报文
        unsigned char dns_pkt[512] = {0};
        HEADER *dns_hdr = (HEADER *)dns_pkt;
        dns_hdr->id = htons(rand() & 0xffff);
        dns_hdr->qr = 0;
        dns_hdr->opcode = 0;
        dns_hdr->rd = 1;
        dns_hdr->qdcount = htons(1);

        unsigned char *cur = dns_pkt + sizeof(HEADER);
        const char *p = domain;
        while (*p)
        {
            const char *start = p;
            while (*p && *p != '.')
                p++;
            *cur++ = p - start;
            memcpy(cur, start, p - start);
            cur += p - start;
            if (*p == '.')
                p++;
        }
        *cur++ = 0;

        uint16_t qtype = htons(ns_t_txt);
        uint16_t qclass = htons(ns_c_in);
        memcpy(cur, &qtype, sizeof(qtype));
        cur += sizeof(qtype);
        memcpy(cur, &qclass, sizeof(qclass));
        cur += sizeof(qclass);

        int pkt_len = cur - dns_pkt;
        sendto(sockfd, dns_pkt, pkt_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

        close(sockfd);

        // 成功发出一个就算成功
        return 0;
    }

    return -1;
}

int extract_final_a_domain(const unsigned char *payload, int len, char *domain_out)
{
    const unsigned char *end = payload + len;
    const unsigned char *ptr = payload + sizeof(HEADER);

    if (len < sizeof(HEADER))
        return -1;

    HEADER *dns = (HEADER *)payload;
    int qdcount = ntohs(dns->qdcount);
    int ancount = ntohs(dns->ancount);

    // 跳过 question 区域
    for (int i = 0; i < qdcount; i++)
    {
        char tmp[MAX_DOMAIN_LEN];
        int n = dn_expand(payload, end, ptr, tmp, sizeof(tmp));
        if (n < 0)
            return -1;
        ptr += n + 4; // 跳过 QTYPE 和 QCLASS
    }

    // 处理 answer 区域
    char final_name[MAX_DOMAIN_LEN] = {0};
    int found = 0;

    for (int i = 0; i < ancount && ptr < end; i++)
    {
        char name[MAX_DOMAIN_LEN];
        int n = dn_expand(payload, end, ptr, name, sizeof(name));
        if (n < 0)
            break;

        ptr += n;

        if (ptr + 10 > end)
            break;

        uint16_t type = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        uint32_t ttl = ntohl(*(uint32_t *)ptr);
        ptr += 4;
        uint16_t rdlength = ntohs(*(uint16_t *)ptr);
        ptr += 2;

        if (ptr + rdlength > end)
            break;

        if (type == T_CNAME)
        {
            // 跟踪 CNAME 指向的新域名
            char cname[MAX_DOMAIN_LEN];
            if (dn_expand(payload, end, ptr, cname, sizeof(cname)) >= 0)
            {
                strcpy(final_name, cname);
                // 重新从头找 cname 的真正 A 记录
                ptr += rdlength;
                printf("Found CNAME: %s\n", cname);
                continue;
            }
            printf("Error: Invalid CNAME record\n");
        }
        else if (type == T_A)
        {
            // 找到 A 记录，返回当前域名
            strcpy(final_name, name);
            found = 1;
            printf("Found A record: %s\n", name);
            break;
        }
        else
            printf("Unknown record type: %d\n", type);

        ptr += rdlength;
    }

    if (found && strlen(final_name) > 0)
    {
        strncpy(domain_out, final_name, MAX_DOMAIN_LEN);
        return 0;
    }

    return -1;
}
