#ifndef PSEUDO_IP_ALLOCATOR_H
#define PSEUDO_IP_ALLOCATOR_H

#include <string>
#include <unordered_map>
#include <queue>
#include <chrono>
#include <optional>

struct Entry {
    std::string domain;
    uint32_t real_ip;  // 修改为 uint32_t 类型
    uint32_t pseudo_ip;
    std::chrono::steady_clock::time_point last_access;
    uint32_t ttl;
};

class PseudoIPAllocator {
public:
    PseudoIPAllocator();

    std::optional<uint32_t> query(const std::string &domain);
    std::optional<uint32_t> allocate(const std::string &domain, uint32_t real_ip, uint32_t ttl);
    std::optional<uint32_t> get_pseudo_ip_from_domain(const std::string &domain);
    std::optional<std::string> get_domain_from_pseudo_ip(uint32_t pseudo_ip_str);

    void cleanup_expired_entries();

private:
    std::unordered_map<std::string, Entry> domain_to_entry;
    std::unordered_map<uint32_t, Entry> ip_to_entry;
    std::queue<uint32_t> free_ips;

    static std::string ip_to_str(uint32_t ip);
};

#endif // PSEUDO_IP_ALLOCATOR_H