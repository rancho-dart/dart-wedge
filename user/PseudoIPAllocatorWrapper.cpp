// PseudoIPAllocatorWrapper.cpp
#include "PseudoIPAllocator.h"
#include <cstring>
#include <map>

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

    uint32_t query_pseudo_ip(const char *domain)
    {
        auto ip = allocator.query(domain);
        if (ip)
        {
            return *ip;
        }
        return 0; // 返回 0 表示失败
    }

    const char *get_domain_by_pseudo_ip(uint32_t pseudo_ip_str)
    {
        static std::string result;
        auto domain = allocator.get_domain_from_pseudo_ip(pseudo_ip_str);
        if (domain)
        {
            result = *domain;
            return result.c_str();
        }
        return nullptr;
    }

    void cleanup_expired()
    {
        allocator.cleanup_expired_entries();
    }
}