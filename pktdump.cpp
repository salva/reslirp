#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h> // For ntohs and inet_ntop
#include <cctype>     // For isprint

#include "utildump.h"
#include "ipdump.h"
#include "pktdump.h"

std::string get_ethertype_name(uint16_t ethertype) {
    switch (ethertype) {
        case 0x0800:
            return "IPv4";
        case 0x86DD:
            return "IPv6";
        case 0x0806:
            return "ARP";
        case 0x8035:
            return "RARP";
        case 0x88CC:
            return "LLDP";
        case 0x8100:
            return "VLAN Tagging (802.1Q)";
        case 0x8809:
            return "STP (Spanning Tree Protocol)";
        case 0x8863:
            return "PPPoE Discovery";
        case 0x8864:
            return "PPPoE Session";
        default:
            return "Unknown";
    }
}

void dispatch_ethertype(const uint8_t* packet, size_t length, uint16_t ethertype, int flags) {
    if (ethertype == 0x0800) {
        dump_ip(packet, length, flags);
    } else if (ethertype == 0x86DD) {
        dump_ip6(packet, length, flags);
    } else if (ethertype == 0x0806) {
        dump_arp(packet, length, flags);
    } else if (ethertype == 0x8035) {
        dump_rarp(packet, length, flags);
    } else if (ethertype == 0x88CC) {
        dump_lldp(packet, length, flags);
    } else if (ethertype == 0x8809) {
        dump_stp(packet, length, flags);
    } else if (ethertype == 0x8100) {
        dump_vlan_tagging(packet, length, flags);
    }
}

void dump_arp(const uint8_t* packet, size_t length, int /* flags */) {
    if (!dump_start("ARP", length, 28)) return;

    uint16_t hw_type = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t proto_type = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint8_t hw_size = packet[4];
    uint8_t proto_size = packet[5];
    uint16_t opcode = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));

    std::string sender_mac = format_mac_address(&packet[8]);
    std::string target_mac = format_mac_address(&packet[18]);
    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &packet[14], sender_ip, sizeof(sender_ip));
    inet_ntop(AF_INET, &packet[24], target_ip, sizeof(target_ip));

    std::cerr << "hw_type:" << hw_type << " proto_type:0x" << std::hex << proto_type << std::dec
              << " hw_size:" << static_cast<int>(hw_size) << " proto_size:" << static_cast<int>(proto_size)
              << " opcode:" << opcode << " sender_mac:" << sender_mac << " sender_ip:" << sender_ip
              << " target_mac:" << target_mac << " target_ip:" << target_ip << std::endl;
}

void dump_rarp(const uint8_t* packet, size_t length, int /* flags */) {
    if (!dump_start("RARP", length, 28)) return;

    uint16_t hw_type = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t proto_type = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint8_t hw_size = packet[4];
    uint8_t proto_size = packet[5];
    uint16_t opcode = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));

    std::string sender_mac = format_mac_address(&packet[8]);
    std::string target_mac = format_mac_address(&packet[18]);
    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &packet[14], sender_ip, sizeof(sender_ip));
    inet_ntop(AF_INET, &packet[24], target_ip, sizeof(target_ip));

    std::cerr << "hw_type:" << hw_type << " proto_type:0x" << std::hex << proto_type << std::dec
              << " hw_size:" << static_cast<int>(hw_size) << " proto_size:" << static_cast<int>(proto_size)
              << " opcode:" << opcode << " sender_mac:" << sender_mac << " sender_ip:" << sender_ip
              << " target_mac:" << target_mac << " target_ip:" << target_ip << std::endl;
}

void dump_vlan_tagging(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("VLAN", length, 4)) return;

    uint16_t tci = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t pcp = (tci >> 13) & 0x07; // Priority Code Point
    uint16_t dei = (tci >> 12) & 0x01; // Drop Eligible Indicator
    uint16_t vid = tci & 0x0FFF;       // VLAN Identifier
    uint16_t ethertype = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));

    std::cerr << "tci:0x" << std::hex << tci << std::dec
              << " pcp:" << pcp << " dei:" << dei << " vid:" << vid
              << " ethertype:0x" << std::hex << ethertype
              << " (" << get_ethertype_name(ethertype) << ")" << std::dec << std::endl;

    dispatch_ethertype(packet + 4, length - 4, ethertype, flags);
}

void dump_ethernet(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("ETH", length, 14)) return;

    std::string dst_mac = format_mac_address(&packet[0]);
    std::string src_mac = format_mac_address(&packet[6]);
    uint16_t ethertype = ntohs(*reinterpret_cast<const uint16_t*>(&packet[12]));

    std::cerr << "dst:" << dst_mac << " src:" << src_mac << " type:0x" << std::hex << ethertype
              << " (" << get_ethertype_name(ethertype) << ")" << std::dec << std::endl;

    dispatch_ethertype(packet + 14, length - 14, ethertype, flags);
}
