#include "pseudo_ip_allocator.h"
#include <iostream>
#include <arpa/inet.h>

PseudoIPAllocator::PseudoIPAllocator() {
    uint32_t start_ip = ntohl(inet_addr("198.18.0.0"));
    uint32_t end_ip = ntohl(inet_addr("198.19.255.255"));

    for (uint32_t ip = start_ip; ip <= end_ip; ++ip) {
        free_ips.push(ip);
    }
}

std::optional<std::string> PseudoIPAllocator::query(const std::string &domain) {
    auto it = domain_to_entry.find(domain);
    if (it != domain_to_entry.end()) {
        it->second.last_access = std::chrono::steady_clock::now();
        return ip_to_str(it->second.pseudo_ip);
    }
    return std::nullopt;
}

std::optional<std::string> PseudoIPAllocator::allocate(const std::string &domain, const std::string &real_ip, uint32_t ttl) {
    if (auto found = query(domain); found.has_value()) return found;

    while (!free_ips.empty()) {
        uint32_t candidate = free_ips.front();
        free_ips.pop();

        if (ip_to_entry.find(candidate) == ip_to_entry.end()) {
            Entry e;
            e.domain = domain;
            e.real_ip = real_ip;
            e.pseudo_ip = candidate;
            e.last_access = std::chrono::steady_clock::now();
            e.ttl = ttl;

            domain_to_entry[domain] = e;
            ip_to_entry[candidate] = e;

            return ip_to_str(candidate);
        }
    }
    return std::nullopt;
}

std::optional<std::string> PseudoIPAllocator::get_domain_from_pseudo_ip(const std::string &pseudo_ip_str) {
    uint32_t ip = ntohl(inet_addr(pseudo_ip_str.c_str()));
    auto it = ip_to_entry.find(ip);
    if (it != ip_to_entry.end()) {
        return it->second.domain;
    }
    return std::nullopt;
}

std::optional<std::string> PseudoIPAllocator::get_pseudo_ip_from_domain(const std::string &domain) {
    return query(domain);
}

void PseudoIPAllocator::cleanup_expired_entries() {
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> to_delete;

    for (const auto &pair : domain_to_entry) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - pair.second.last_access).count();
        if (elapsed > pair.second.ttl) {
            to_delete.push_back(pair.first);
        }
    }

    for (const auto &domain : to_delete) {
        uint32_t ip = domain_to_entry[domain].pseudo_ip;
        domain_to_entry.erase(domain);
        ip_to_entry.erase(ip);
        free_ips.push(ip);
    }
}

std::string PseudoIPAllocator::ip_to_str(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return inet_ntoa(addr);
}
