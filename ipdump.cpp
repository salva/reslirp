#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h> // For ntohs and inet_ntop
#include <cctype>     // For isprint

#include "utildump.h"
#include "appdump.h"
#include "ipdump.h"

std::string protocol_name(int protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 88: return "EIGRP";
        case 89: return "OSPF";
        case 115: return "L2TP";
        case 132: return "SCTP";
        case 137: return "MPLS-in-IP";
        default: return "Unknown";
    }
}

std::string icmp_type_name(uint8_t type, bool is_v6) {
    if (is_v6) {
        switch (type) {
            case 128: return "Echo Request";
            case 129: return "Echo Reply";
            case 133: return "Router Solicitation";
            case 134: return "Router Advertisement";
            case 135: return "Neighbor Solicitation";
            case 136: return "Neighbor Advertisement";
            case 137: return "Redirect";
            case 143: return "Multicast Listener Report";
            default: return "Unknown";
        }
    } else {
        switch (type) {
            case 8: return "Echo Request";
            case 0: return "Echo Reply";
            case 3: return "Destination Unreachable";
            case 4: return "Source Quench";
            case 5: return "Redirect";
            case 11: return "Time Exceeded";
            case 12: return "Parameter Problem";
            default: return "Unknown";
        }
    }
}

void dispatch_protocol(const uint8_t* packet, size_t length, int protocol, int flags) {
    switch (protocol) {
        case 6:  // TCP
            dump_tcp(packet, length, flags);
            break;
        case 17: // UDP
            dump_udp(packet, length, flags);
            break;
        case 1:  // ICMP
            dump_icmp(packet, length, flags);
            break;
        case 58: // ICMPv6
            dump_icmpv6(packet, length, flags);
            break;
        case 132: // SCTP
            dump_sctp(packet, length, flags);
            break;
        case 115: // L2TP
            dump_l2tp(packet, length, flags);
            break;
        default:
            std::cerr << "[Payload not decoded for protocol: " << protocol << " (" << protocol_name(protocol) << ")" << "]" << std::endl;
            break;
    }
}

void dump_ip(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("IPv4", length, 20)) return;

    uint8_t version_and_ihl = packet[0];
    uint8_t version = (version_and_ihl >> 4) & 0xF;
    uint8_t ihl = version_and_ihl & 0xF;

    uint16_t total_length = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint8_t ttl = packet[8];
    uint8_t protocol = packet[9];
    uint16_t header_checksum = ntohs(*reinterpret_cast<const uint16_t*>(&packet[10]));

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &packet[12], src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &packet[16], dst_ip, sizeof(dst_ip));

    std::cerr << "ver:" << static_cast<int>(version)
              << " ihl:" << static_cast<int>(ihl * 4)
              << " tot_len:" << total_length
              << " ttl:" << static_cast<int>(ttl)
              << " proto:" << static_cast<int>(protocol)
              << " (" << protocol_name(protocol) << ") checksum:0x" << std::hex << header_checksum << std::dec
              << " src:" << src_ip
              << " dst:" << dst_ip << std::endl;

    size_t ip_header_length = ihl * 4;

    if (ip_header_length > length) {
        std::cerr << "[IPv4 header truncated]" << std::endl;
        return;
    }

    if (ihl > 5) {
        std::cerr << "options:";
        for (size_t i = 20; i < ip_header_length; ++i) {
            std::cerr << " 0x" << std::hex << static_cast<int>(packet[i]) << std::dec;
        }
        std::cerr << std::endl;
    }

    size_t ip_payload_length = total_length - ip_header_length;
    dispatch_protocol(packet + ip_header_length, ip_payload_length, protocol, flags);
}
void dump_ip6(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("IPv6", length, 40)) return;

    uint8_t version = (packet[0] >> 4) & 0xF;
    uint16_t payload_length = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));
    uint8_t next_header = packet[6];
    uint8_t hop_limit = packet[7];

    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &packet[8], src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &packet[24], dst_ip, sizeof(dst_ip));

    std::cerr << "ver:" << static_cast<int>(version) << " plen:" << payload_length
              << " nh:" << (int)next_header << " (" << protocol_name(next_header) << ") hlim:" << static_cast<int>(hop_limit)
              << " src:" << src_ip << " dst:" << dst_ip << std::endl;

    if ((size_t)(payload_length) + 40 > length) {
        std::cerr << "[IPv6 payload truncated]" << std::endl;
        return;
    }

    size_t offset = 40; // start after the IPv6 header
    while (next_header == 0 && offset < length) { // handle hop-by-hop options
        if (offset + 8 > length) {
            std::cerr << "[IPv6 options truncated]" << std::endl;
            return;
        }
        uint8_t hdr_ext_length = packet[offset + 1]; // length in units of 8 bytes, not including the first 8 bytes
        std::cerr << "[Hop-by-Hop Options: next header " << static_cast<int>(packet[offset])
                  << ", length " << static_cast<int>(hdr_ext_length) << "]" << std::endl;
        next_header = packet[offset];
        offset += (hdr_ext_length + 1) * 8;
    }

    if (offset >= length) {
        std::cerr << "[IPv6 packet truncated after options]" << std::endl;
        return;
    }

    dispatch_protocol(packet + offset, length - offset, next_header, flags);
}

void dump_icmp(const uint8_t* packet, size_t length, int /* flags */) {
    if (!dump_start("ICMP", length, 8)) return;

    uint8_t type = packet[0];
    uint8_t code = packet[1];
    uint16_t checksum = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));

    std::cerr << "type:" << static_cast<int>(type) << " (" << icmp_type_name(type, false) << ") "
              << "code:" << static_cast<int>(code) << " checksum:0x" << std::hex << checksum << std::dec << std::endl;

    if (type == 8 || type == 0) { // Echo Request and Reply
        if (length >= 8) {
            uint16_t identifier = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));
            uint16_t sequence_number = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));
            std::cerr << "    identifier:" << identifier << " sequence_number:" << sequence_number << std::endl;
        } else {
            std::cerr << "    [Truncated ICMP echo payload]" << std::endl;
        }
    } else if (type == 3) { // Destination Unreachable
        if (length >= 8) {
            uint32_t unused = ntohl(*reinterpret_cast<const uint32_t*>(&packet[4]));
            std::cerr << "    Destination Unreachable, unused:" << unused << std::endl;
        } else {
            std::cerr << "    [Truncated ICMP destination unreachable payload]" << std::endl;
        }
    } else if (type == 11) { // Time Exceeded
        if (length >= 8) {
            uint32_t unused = ntohl(*reinterpret_cast<const uint32_t*>(&packet[4]));
            std::cerr << "    Time Exceeded, unused:" << unused << std::endl;
        } else {
            std::cerr << "    [Truncated ICMP time exceeded payload]" << std::endl;
        }
    } else {
        std::cerr << "    [Unrecognized ICMP type: no additional decoding]" << std::endl;
    }
}

void dump_icmpv6(const uint8_t* packet, size_t length, int /* flags */) {
    if (!dump_start("ICMPv6", length, 8)) return;

    uint8_t type = packet[0];
    uint8_t code = packet[1];
    uint16_t checksum = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));

    std::cerr << "type:" << static_cast<int>(type) << " (" << icmp_type_name(type, true) << ") "
              << "code:" << static_cast<int>(code) << " checksum:0x" << std::hex << checksum << std::dec << std::endl;

    switch (type) {
        case 128: // Echo Request
        case 129: // Echo Reply
            if (length >= 8) {
                uint16_t identifier = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));
                uint16_t sequence_number = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));
                std::cerr << "    identifier:" << identifier << " sequence_number:" << sequence_number << std::endl;
            } else {
                std::cerr << "    [Truncated ICMPv6 echo payload]" << std::endl;
            }
            break;
        case 134: // Router Advertisement
            if (length >= 16) {
                uint8_t cur_hop_limit = packet[4];
                uint8_t flags = packet[5];
                uint16_t router_lifetime = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));
                uint32_t reachable_time = ntohl(*reinterpret_cast<const uint32_t*>(&packet[8]));
                uint32_t retrans_timer = ntohl(*reinterpret_cast<const uint32_t*>(&packet[12]));
                std::cerr << "    cur_hop_limit:" << static_cast<int>(cur_hop_limit)
                          << " flags:0x" << std::hex << static_cast<int>(flags)
                          << " router_lifetime:" << std::dec << router_lifetime
                          << " reachable_time:" << reachable_time
                          << " retrans_timer:" << retrans_timer << std::endl;
            } else {
                std::cerr << "    [Truncated Router Advertisement]" << std::endl;
            }
            break;
        case 135: // Neighbor Solicitation
            if (length >= 24) {
                uint32_t reserved = ntohl(*reinterpret_cast<const uint32_t*>(&packet[4]));
                char target_address[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &packet[8], target_address, INET6_ADDRSTRLEN);
                std::cerr << "    reserved:0x" << std::hex << reserved
                          << " target:" << target_address << std::dec << std::endl;
            } else {
                std::cerr << "    [Truncated Neighbor Solicitation]" << std::endl;
            }
            break;
        case 136: // Neighbor Advertisement
            if (length >= 24) {
                uint32_t flags_reserved = ntohl(*reinterpret_cast<const uint32_t*>(&packet[4]));
                char target_address[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &packet[8], target_address, INET6_ADDRSTRLEN);
                std::cerr << "    flags_reserved:0x" << std::hex << flags_reserved
                          << " target:" << target_address << std::dec << std::endl;
            } else {
                std::cerr << "    [Truncated Neighbor Advertisement]" << std::endl;
            }
            break;
        case 143: // Multicast Listener Report Message v2
            if (length >= 8) {
                uint16_t reserved = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));
                uint16_t num_records = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));
                std::cerr << "    reserved:0x" << std::hex << reserved
                          << " number_of_records:" << std::dec << num_records << std::endl;
                // Further parsing of records can be implemented here as needed
            } else {
                std::cerr << "    [Truncated Multicast Listener Report]" << std::endl;
            }
            break;
        // Add other ICMPv6 message types as needed
        default:
            std::cerr << "    [Unsupported ICMPv6 message type]" << std::endl;
            break;
    }
}

void dump_tcp(const uint8_t* packet, size_t length, int /* flags */) {
    if (!dump_start("TCP", length, 20)) return;

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
    if (!dump_start("UDP", length, 8)) return;

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


