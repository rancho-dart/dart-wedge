#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 只暴露 C 能理解的简单结构
typedef struct PseudoIPEntryC {
    const char* domain;    // 指向C字符串
    uint32_t pseudo_ip;    // 伪地址 (host字节序)
    uint32_t real_ip;      // 真实IP (host字节序)
} PseudoIPEntryC;

// 初始化分配器
void pseudo_ip_allocator_init();

// 根据域名分配或查询伪地址，返回Entry
const PseudoIPEntryC* pseudo_ip_allocator_allocate(const char* domain, uint32_t real_ip);

// 根据伪地址查询
const PseudoIPEntryC* pseudo_ip_allocator_find_by_pseudo_ip(uint32_t pseudo_ip);

// 根据域名查询
const PseudoIPEntryC* pseudo_ip_allocator_find_by_domain(const char* domain);

// 释放一个域名
void pseudo_ip_allocator_release_by_domain(const char* domain);

// 周期性清理（传入当前时间戳）
void pseudo_ip_allocator_cleanup(uint64_t now);

// 判断IP是否在伪地址池中
bool is_pseudo_ip(uint32_t ip);


#ifdef __cplusplus
}
#endif
