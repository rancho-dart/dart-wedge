// pseudo_ip_allocator.h
#ifndef PSEUDO_IP_ALLOCATOR_H
#define PSEUDO_IP_ALLOCATOR_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <chrono>
#include <optional>

class PseudoIPAllocator {
public:
    struct AllocInfo {
        std::string domain;
        std::string real_ip;
        std::chrono::steady_clock::time_point last_access;
        int ttl; // seconds
    };

    PseudoIPAllocator();

    // 分配一个伪地址给域名，或返回已分配的
    uint32_t allocate(const std::string& domain, const std::string& real_ip, int ttl);

    // 查询伪地址对应的域名
    std::optional<std::string> query_domain(uint32_t ip);

    // 查询域名对应的伪地址（如果已分配）
    std::optional<uint32_t> query_ip(const std::string& domain);

    // 清理TTL过期的条目
    void cleanup_expired();

private:
    std::queue<uint32_t> free_ips;
    std::unordered_map<std::string, uint32_t> domain_to_ip;
    std::unordered_map<uint32_t, AllocInfo> ip_to_info;

    const uint32_t ip_start = (198 << 24) | (18 << 16); // 198.18.0.0
    const uint32_t ip_end   = (198 << 24) | (19 << 16) | 0xFFFF; // 198.19.255.255
};

#endif // PSEUDO_IP_ALLOCATOR_H
