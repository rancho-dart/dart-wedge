#pragma once
#include <unordered_map>
#include <string>
#include <cstdint>

struct PseudoIPEntry {
    std::string domain;
    uint32_t pseudo_ip;
    uint32_t real_ip;
    uint64_t timestamp;
};

class PseudoIPAllocator {
public:
    PseudoIPAllocator();
    ~PseudoIPAllocator();

    // 根据域名分配伪地址
    PseudoIPEntry* allocate(const std::string& domain, uint32_t real_ip);

    // 根据伪地址查询信息
    const PseudoIPEntry* find_by_pseudo_ip(uint32_t pseudo_ip) const;

    // 根据域名查询信息
    const PseudoIPEntry* find_by_domain(const std::string& domain) const;

    // 回收伪地址
    bool release_by_domain(const std::string& domain);

    // 定期清理过期项
    void cleanup(uint64_t now);

private:
    uint32_t next_ip();
    std::unordered_map<std::string, PseudoIPEntry> domain_to_entry;
    std::unordered_map<uint32_t, PseudoIPEntry*> ip_to_entry;
    uint32_t last_allocated;
};
