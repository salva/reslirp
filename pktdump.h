#ifndef PKTDUMP_H
#define PKTDUMP_H

#include <cstdint>
#include <cstddef> // For size_t

void dump_ethernet(const uint8_t* packet, size_t length, int flags);
void dump_arp(const uint8_t* packet, size_t length, int flags);
void dump_rarp(const uint8_t* packet, size_t length, int flags);
void dump_lldp(const uint8_t* packet, size_t length, int flags);
void dump_stp(const uint8_t* packet, size_t length, int flags);
void dump_vlan_tagging(const uint8_t* packet, size_t length, int flags);

#endif // PKTDUMP_H
