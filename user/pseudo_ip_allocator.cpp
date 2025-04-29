#include <netinet/in.h> // ntohl, htonl
#include <arpa/inet.h>  // 添加此行以支持 inet_ntoa
#include <cstring>      // memset
#include <stdexcept>
#include <iostream>
#include "pseudo_ip_allocator.h"

PseudoIPAllocator::PseudoIPAllocator()
    : last_allocated(0) {}

PseudoIPAllocator::~PseudoIPAllocator() {}

PseudoIPEntry *PseudoIPAllocator::allocate(const std::string &domain, nbo_ipv4_t real_ip)
{
    auto it = domain_to_entry.find(domain);
    if (it != domain_to_entry.end())
    {
        return &(it->second);
    }

    nbo_ipv4_t ip = next_ip();
    PseudoIPEntry entry{domain, ip, real_ip, 0 /*timestamp后面设*/};
    domain_to_entry.emplace(domain, entry);
    ip_to_entry[ip] = &domain_to_entry[domain];
    return &domain_to_entry[domain];
}

const PseudoIPEntry *PseudoIPAllocator::find_by_pseudo_ip(nbo_ipv4_t pseudo_ip) const
{
    auto it = ip_to_entry.find(pseudo_ip);
    if (it != ip_to_entry.end())
    {
        return it->second;
    }
    printf("Currently in ip_to_entry: \n");
    // 如果没有找到，打印出ip_to_entry所有的条目(包括domain和IP，IP转换点分割形式)
    for (auto it = ip_to_entry.begin(); it != ip_to_entry.end(); ++it)
    {
        printf("IP: %s, Domain: %s\n", inet_ntoa(*(in_addr *)&it->first), it->second->domain.c_str());
    }
    return nullptr;
}

const PseudoIPEntry *PseudoIPAllocator::find_by_domain(const std::string &domain) const
{
    auto it = domain_to_entry.find(domain);
    if (it != domain_to_entry.end())
    {
        return &(it->second);
    }
    return nullptr;
}

bool PseudoIPAllocator::release_by_domain(const std::string &domain)
{
    auto it = domain_to_entry.find(domain);
    if (it == domain_to_entry.end())
    {
        return false;
    }
    uint32_t ip = it->second.pseudo_ip;
    ip_to_entry.erase(ip);
    domain_to_entry.erase(it);
    return true;
}

nbo_ipv4_t PseudoIPAllocator::next_ip()
{
    for (uint32_t i = 0; i < PSEUDO_IP_POOL_SIZE - 1; ++i)
    { // 避免死循环
        last_allocated++;
        if (last_allocated >= PSEUDO_IP_POOL_SIZE)
        {
            last_allocated = 1;
        }
        if (ip_to_entry.count(PSEUDO_IP_BASE + last_allocated) == 0)
        {
            return htonl(PSEUDO_IP_BASE + last_allocated);
        }
    }

    throw std::runtime_error("PseudoIPAllocator: address pool exhausted");
}

bool PseudoIPAllocator::is_pseudo_ip(nbo_ipv4_t ip)
{
    hbo_ipv4_t hbo_ip = ntohl(ip);
    return (hbo_ip & PSEUDO_IP_MASK) == PSEUDO_IP_BASE;
}

void PseudoIPAllocator::cleanup(uint64_t now)
{
    for (auto it = domain_to_entry.begin(); it != domain_to_entry.end();)
    {
        if (now - it->second.timestamp > 60)
        {
            uint32_t ip = it->second.pseudo_ip;
            ip_to_entry.erase(ip);
            it = domain_to_entry.erase(it);
        }
        else
        {
            ++it;
        }
    }
}
