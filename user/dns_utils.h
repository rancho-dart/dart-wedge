#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "common.h"

#define DNS_PORT 53
#define DHCP_PORT 67
#define MAX_DOMAIN_LEN 256

#define DNS_MAX_NAME_LENGTH 255
#define DNS_MAX_NAME_LENGTH_WITH_TERMINATOR (DNS_MAX_NAME_LENGTH + 1)

#define DNS_MAX_LABEL_LENGTH 63
#define DNS_MAX_LABEL_LENGTH_WITH_TERMINATOR (DNS_MAX_LABEL_LENGTH + 1)

#define MAX_DNS_SERVERS 3
#define DNS_CONF_PATH "/etc/resolv.conf"

extern nbo_ipv4_t g_dns_servers[MAX_DNS_SERVERS] ;
extern int g_dns_server_count ;

bool init_dns_servers();

// bool is_txt_record_response(const unsigned char *dns_pkt, size_t len, int *version, char *domain);
// bool is_a_record_response(const unsigned char *payload, size_t len, char *domain);
void hex_dump(const char *msg, const unsigned char *data, size_t len);
int follow_cname_chain(const unsigned char *payload, int len, char *domain_out, char *cname_out, struct in_addr *ip_out, int *a_record_pos);

void get_full_fqdn(char *fqdn);

#endif // DNS_UTILS_H