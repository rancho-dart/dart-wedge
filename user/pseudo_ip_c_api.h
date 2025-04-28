#ifndef PSEUDO_IP_C_API_H
#define PSEUDO_IP_C_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t allocate_pseudo_ip(const char* domain, uint32_t real_ip, uint32_t ttl);
uint32_t query_pseudo_ip(const char* domain);
const char* get_domain_by_pseudo_ip(uint32_t pseudo_ip_str);
void cleanup_expired();

#ifdef __cplusplus
}
#endif

#endif // PSEUDO_IP_C_API_H
