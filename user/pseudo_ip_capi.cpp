#include "pseudo_ip_allocator.h"
#include "pseudo_ip_capi.h"
#include <netinet/in.h>

// 单例
static PseudoIPAllocator g_allocator;

void pseudo_ip_allocator_init() {
    // g_allocator已经自动构造，不需要特别处理
}

const PseudoIPEntryC* pseudo_ip_allocator_allocate(const char* domain, uint32_t real_ip) {
    static PseudoIPEntryC entry_c;
    auto* entry = g_allocator.allocate(domain, real_ip);
    if (entry) {
        entry_c.domain = entry->domain.c_str();
        entry_c.pseudo_ip = entry->pseudo_ip;
        entry_c.real_ip = entry->real_ip;
        return &entry_c;
    }
    return nullptr;
}

const PseudoIPEntryC* pseudo_ip_allocator_find_by_pseudo_ip(uint32_t pseudo_ip) {
    static PseudoIPEntryC entry_c;
    auto* entry = g_allocator.find_by_pseudo_ip(pseudo_ip);
    if (entry) {
        entry_c.domain = entry->domain.c_str();
        entry_c.pseudo_ip = entry->pseudo_ip;
        entry_c.real_ip = entry->real_ip;
        return &entry_c;
    }
    return nullptr;
}

const PseudoIPEntryC* pseudo_ip_allocator_find_by_domain(const char* domain) {
    static PseudoIPEntryC entry_c;
    auto* entry = g_allocator.find_by_domain(domain);
    if (entry) {
        entry_c.domain = entry->domain.c_str();
        entry_c.pseudo_ip = entry->pseudo_ip;
        entry_c.real_ip = entry->real_ip;
        return &entry_c;
    }
    return nullptr;
}

void pseudo_ip_allocator_release_by_domain(const char* domain) {
    g_allocator.release_by_domain(domain);
}

void pseudo_ip_allocator_cleanup(uint64_t now) {
    g_allocator.cleanup(now);
}

bool is_pseudo_ip(uint32_t ip) {
    ip = ntohl(ip); // 转为主机字节序再判断
    return (ip >= 0xC6120000 && ip <= 0xC613FFFF); // 198.18.0.0 ~ 198.19.255.255
}
