#include "pseudo_ip_allocator.h"
#include <netinet/in.h> // ntohl, htonl
#include <cstring> // memset

PseudoIPAllocator::PseudoIPAllocator()
    : last_allocated(0) {}

PseudoIPAllocator::~PseudoIPAllocator() {}

PseudoIPEntry* PseudoIPAllocator::allocate(const std::string& domain, uint32_t real_ip) {
    auto it = domain_to_entry.find(domain);
    if (it != domain_to_entry.end()) {
        return &(it->second);
    }

    uint32_t ip = next_ip();
    PseudoIPEntry entry { domain, ip, real_ip, 0 /*timestamp后面设*/ };
    domain_to_entry.emplace(domain, entry);
    ip_to_entry[ip] = &domain_to_entry[domain];
    return &domain_to_entry[domain];
}

const PseudoIPEntry* PseudoIPAllocator::find_by_pseudo_ip(uint32_t pseudo_ip) const {
    auto it = ip_to_entry.find(pseudo_ip);
    if (it != ip_to_entry.end()) {
        return it->second;
    }
    return nullptr;
}

const PseudoIPEntry* PseudoIPAllocator::find_by_domain(const std::string& domain) const {
    auto it = domain_to_entry.find(domain);
    if (it != domain_to_entry.end()) {
        return &(it->second);
    }
    return nullptr;
}

bool PseudoIPAllocator::release_by_domain(const std::string& domain) {
    auto it = domain_to_entry.find(domain);
    if (it == domain_to_entry.end()) {
        return false;
    }
    uint32_t ip = it->second.pseudo_ip;
    ip_to_entry.erase(ip);
    domain_to_entry.erase(it);
    return true;
}

uint32_t PseudoIPAllocator::next_ip() {
    // 简单从198.18.0.0递增
    const uint32_t base = (198 << 24) | (18 << 16);
    do {
        last_allocated++;
        if (last_allocated >= 0x1FFFF) {
            last_allocated = 1;
        }
    } while (ip_to_entry.count(base + last_allocated));
    return base + last_allocated;
}
