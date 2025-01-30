#ifndef IPDUMP_H
#define IPDUMP_H

#include <cstdint>
#include <cstddef> // For size_t

void dump_ip(const uint8_t* packet, size_t length, int flags);
void dump_ip6(const uint8_t* packet, size_t length, int flags);
void dump_icmp(const uint8_t* packet, size_t length, int flags);
void dump_icmpv6(const uint8_t* packet, size_t length, int flags);
void dump_tcp(const uint8_t* packet, size_t length, int flags);
void dump_udp(const uint8_t* packet, size_t length, int flags);
void dump_sctp(const uint8_t* packet, size_t length, int flags);
void dump_l2tp(const uint8_t* packet, size_t length, int flags);

#endif // IPDUMP_H
