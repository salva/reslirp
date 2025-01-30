#ifndef APPDUMP_H
#define APPDUMP_H

#include <cstdint>
#include <cstddef> // For size_t

void dump_dhcp(const uint8_t* packet, size_t length, int flags);
void dump_dns(const uint8_t* packet, size_t length, int flags);
void dump_dhcp_load(const uint8_t* packet, size_t length, int flags);
void dump_dns_load(const uint8_t* packet, size_t length, int flags);

#endif // APPDUMP_H
