#include "pktdump.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h> // For ntohs and inet_ntop
#include <cctype>     // For isprint

enum DumpFlags {
    DUMP_BASIC = 0x0,
    DUMP_DHCP = 0x1,
    DUMP_DNS = 0x2
};

// Helper function to start layer and check length
bool start_layer(const std::string& layer, size_t length, size_t expected) {
    std::cerr << layer << " (" << length;
    if (length < expected) {
        std::cerr << " < " << expected << ")" << std::endl;
        return false;
    }
    std::cerr << "B): ";
    return true;
}

void dump_ethernet(const uint8_t* packet, size_t length) {
    if (!start_layer("ETH", length, 14)) return;

    char src_mac[18], dst_mac[18];
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             packet[0], packet[1], packet[2],
             packet[3], packet[4], packet[5]);
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             packet[6], packet[7], packet[8],
             packet[9], packet[10], packet[11]);

    uint16_t ethertype = ntohs(*reinterpret_cast<const uint16_t*>(&packet[12]));

    std::cerr << "dst:" << dst_mac << " src:" << src_mac << " type:0x" << std::hex << ethertype << std::dec << std::endl;

    packet += 14;
    length -= 14;

    if (ethertype == 0x0800) {
        dump_ip(packet, length, 0);
    } else if (ethertype == 0x86DD) {
        dump_ip6(packet, length, 0);
    }
}

void dump_ip(const uint8_t* packet, size_t length, int flags) {
    if (!start_layer("IPv4", length, 20)) return;

    uint8_t version_and_ihl = packet[0];
    uint8_t version = (version_and_ihl >> 4) & 0xF;
    uint8_t ihl = version_and_ihl & 0xF;

    uint16_t total_length = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint8_t protocol = packet[9];

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &packet[12], src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &packet[16], dst_ip, sizeof(dst_ip));

    std::cerr << "ver:" << static_cast<int>(version) << " ihl:" << static_cast<int>(ihl * 4)
              << " tot_len:" << total_length << " proto:" << static_cast<int>(protocol)
              << " src:" << src_ip << " dst:" << dst_ip << std::endl;

    size_t ip_header_length = ihl * 4;
    size_t ip_payload_length = total_length - ip_header_length;

    if (protocol == 6) {
        dump_tcp(packet + ip_header_length, ip_payload_length, flags);
    } else if (protocol == 17) {
        dump_udp(packet + ip_header_length, ip_payload_length, flags);
    } else if (protocol == 1) {
        dump_icmp(packet + ip_header_length, ip_payload_length, flags);
    }
}

void dump_ip6(const uint8_t* packet, size_t length, int flags) {
    if (!start_layer("IPv6", length, 40)) return;

    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &packet[8], src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &packet[24], dst_ip, sizeof(dst_ip));

    uint8_t next_header = packet[6];
    uint16_t payload_length = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));

    std::cerr << "plen:" << payload_length << " nh:" << static_cast<int>(next_header)
              << " src:" << src_ip << " dst:" << dst_ip << std::endl;

    if (next_header == 6) {
        dump_tcp(packet + 40, length - 40, flags);
    } else if (next_header == 17) {
        dump_udp(packet + 40, length - 40, flags);
    } else if (next_header == 58) {
        dump_icmp(packet + 40, length - 40, flags);
    }
}

void dump_tcp(const uint8_t* packet, size_t length, int flags) {
    if (!start_layer("TCP", length, 20)) return;

    uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint32_t seq_num = ntohl(*reinterpret_cast<const uint32_t*>(&packet[4]));
    uint32_t ack_num = ntohl(*reinterpret_cast<const uint32_t*>(&packet[8]));
    uint16_t flags_field = ntohs(*reinterpret_cast<const uint16_t*>(&packet[12])) & 0x3F; // Last 6 bits for flags

    std::cerr << "src_port:" << src_port << " dst_port:" << dst_port
              << " seq:" << seq_num << " ack:" << ack_num
              << " flags:" << flags_field << " [";
    if (flags_field & 0x01) std::cerr << "FIN ";
    if (flags_field & 0x02) std::cerr << "SYN ";
    if (flags_field & 0x04) std::cerr << "RST ";
    if (flags_field & 0x08) std::cerr << "PSH ";
    if (flags_field & 0x10) std::cerr << "ACK ";
    if (flags_field & 0x20) std::cerr << "URG ";
    std::cerr << "]" << std::endl;
}

void dump_udp(const uint8_t* packet, size_t length, int flags) {
    if (!start_layer("UDP", length, 8)) return;

    uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint16_t udp_length = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));

    std::cerr << "src_port:" << src_port << " dst_port:" << dst_port << " len:" << udp_length << std::endl;

    if ((flags & DUMP_DHCP) && (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68)) {
        dump_dhcp(packet + 8, length - 8, flags);
    } else if ((flags & DUMP_DNS) && (src_port == 53 || dst_port == 53)) {
        dump_dns(packet + 8, length - 8, flags);
    }
}

void dump_icmp(const uint8_t* packet, size_t length, int flags) {
    if (!start_layer("ICMP", length, 8)) return;

    uint8_t type = packet[0];
    uint8_t code = packet[1];
    uint16_t checksum = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));

    std::cerr << "type:" << static_cast<int>(type) << " code:" << static_cast<int>(code)
              << " checksum:0x" << std::hex << checksum << std::dec << std::endl;
}

void dump_dhcp(const uint8_t* packet, size_t length, int flags) {
    if (!start_layer("DHCP", length, 240)) return;

    uint8_t op = packet[0];
    uint8_t htype = packet[1];
    uint8_t hlen = packet[2];
    uint8_t hops = packet[3];

    uint32_t xid = ntohl(*reinterpret_cast<const uint32_t*>(&packet[4]));
    uint16_t secs = ntohs(*reinterpret_cast<const uint16_t*>(&packet[8]));
    uint16_t flags_field = ntohs(*reinterpret_cast<const uint16_t*>(&packet[10]));

    std::cerr << "op:" << static_cast<int>(op) << " htype:" << static_cast<int>(htype)
              << " hlen:" << static_cast<int>(hlen) << " hops:" << static_cast<int>(hops)
              << " xid:" << xid << " secs:" << secs << " flags:0x" << std::hex << flags_field << std::dec << std::endl;

    dump_dhcp_load(packet, length);
}

void dump_dns(const uint8_t* packet, size_t length, int flags) {
    if (!start_layer("DNS", length, 12)) return;

    uint16_t transaction_id = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t flags_field = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint16_t questions = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));
    uint16_t answers = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));

    std::cerr << "id:" << transaction_id << " flags:0x" << std::hex << flags_field << std::dec
              << " qdcount:" << questions << " ancount:" << answers << std::endl;

    dump_dns_load(packet, length);
}

// Placeholder functions for DHCP and DNS detailed loading
void dump_dhcp_load(const uint8_t* packet, size_t length) {
    std::cerr << "[Detailed DHCP data not yet implemented]" << std::endl;
}

void dump_dns_load(const uint8_t* packet, size_t length) {
    std::cerr << "[Detailed DNS data not yet implemented]" << std::endl;
}
