#pragma once
#include <unordered_map>
#include <string>
#include <cstdint>

#define PSEUDO_IP_BASE        ((198U << 24) | (18U << 16)) // 198.18.0.0
#define PSEUDO_IP_MASK        0xFFFE0000U                  // /15 子网掩码
#define PSEUDO_IP_POOL_SIZE   0x20000U                     // 2^17 = 131072 地址

typedef uint32_t nbo_ipv4_t;  // Network Byte Order IPv4 address
typedef uint16_t nbo_port_t;  // Network Byte Order Port
typedef uint32_t hbo_ipv4_t;  // Host Byte Order IPv4 address
typedef uint16_t hbo_port_t;  // Host Byte Order Port

struct PseudoIPEntry {
    std::string domain;
    nbo_ipv4_t pseudo_ip;
    nbo_ipv4_t real_ip;
    uint64_t timestamp;
};


class PseudoIPAllocator {
public:
    PseudoIPAllocator();
    ~PseudoIPAllocator();

    // 根据域名分配伪地址
    PseudoIPEntry* allocate(const std::string& domain, nbo_ipv4_t real_ip);

    // 根据伪地址查询信息
    const PseudoIPEntry* find_by_pseudo_ip(nbo_ipv4_t pseudo_ip) const;

    // 根据域名查询信息
    const PseudoIPEntry* find_by_domain(const std::string& domain) const;

    // 回收伪地址
    bool release_by_domain(const std::string& domain);

    // 定期清理过期项
    void cleanup(uint64_t now);

    bool is_pseudo_ip(nbo_ipv4_t ip);


private:
    nbo_ipv4_t next_ip();
    std::unordered_map<std::string, PseudoIPEntry> domain_to_entry;
    std::unordered_map<uint32_t, PseudoIPEntry*> ip_to_entry;
    hbo_ipv4_t last_allocated;  // Host Byte Order。因为会有+1操作，因此保持为hbo
};
