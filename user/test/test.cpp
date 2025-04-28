#include "PseudoIPAllocator.h"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    PseudoIPAllocator allocator;

    std::string domain = "example.com";
    std::string real_ip = "93.184.216.34";
    uint32_t ttl = 5; // seconds

    // 分配伪地址
    auto pseudo_ip = allocator.allocate(domain, real_ip, ttl);
    if (pseudo_ip) {
        std::cout << "Allocated pseudo IP: " << *pseudo_ip << std::endl;
    } else {
        std::cerr << "Failed to allocate pseudo IP" << std::endl;
        return 1;
    }

    // 查询伪地址
    auto queried_ip = allocator.query(domain);
    if (queried_ip) {
        std::cout << "Queried pseudo IP: " << *queried_ip << std::endl;
    } else {
        std::cerr << "Failed to query pseudo IP" << std::endl;
    }

    // 查询域名
    auto queried_domain = allocator.get_domain_from_pseudo_ip(*pseudo_ip);
    if (queried_domain) {
        std::cout << "Reverse lookup domain: " << *queried_domain << std::endl;
    } else {
        std::cerr << "Failed to reverse lookup domain" << std::endl;
    }

    // 等待TTL过期
    std::cout << "Waiting for TTL to expire...\n";
    std::this_thread::sleep_for(std::chrono::seconds(ttl + 1));

    allocator.cleanup_expired_entries();

    // 再次查询应失败
    auto expired_ip = allocator.query(domain);
    if (!expired_ip) {
        std::cout << "Entry expired and cleaned up as expected." << std::endl;
    } else {
        std::cerr << "Error: entry should have expired." << std::endl;
    }

    return 0;
} 
