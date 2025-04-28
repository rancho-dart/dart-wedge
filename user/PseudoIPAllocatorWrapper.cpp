// PseudoIPAllocatorWrapper.cpp
#include "PseudoIPAllocator.h"
#include <cstring>
#include <map>

// 定义结构体 DomainInfo
struct DomainInfo {
    std::string domain;
    uint32_t real_ip;
};

extern "C"
{

    // 全局实例（线程不安全，仅用于简单示例）
    static PseudoIPAllocator allocator;

    uint32_t allocate_pseudo_ip(const char *domain, uint32_t real_ip, uint32_t ttl)
    {
        auto ip = allocator.allocate(domain, real_ip, ttl);
        if (ip)
        {
            return *ip;
        }
        return 0; // 返回 0 表示失败
    }

    bool is_pseudo_ip(uint32_t ip)
    {
        auto is = allocator.is_pseudo_ip(ip);
        if (is)
        {
            return is;
        }
        return false;
    }
    uint32_t query_pseudo_ip(const char *domain)
    {
        auto ip = allocator.query(domain);
        if (ip)
        {
            return *ip;
        }
        return 0; // 返回 0 表示失败
    }

    // 修改 get_domain_by_pseudo_ip 函数以返回 DomainInfo 结构体
    DomainInfo get_domain_by_pseudo_ip(uint32_t pseudo_ip_str)
    {
        DomainInfo result;
        auto domain_pair = allocator.get_domain_from_pseudo_ip(pseudo_ip_str);
        if (domain_pair)
        {
            result.domain = domain_pair->first;
            result.real_ip = domain_pair->second;
        }
        return result;
    }

    void cleanup_expired()
    {
        allocator.cleanup_expired_entries();
    }
}