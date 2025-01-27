#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h> // For ntohs and inet_ntop
#include "utildump.h"
#include "pktdump.h"

void dump_lldp(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("LLDP", length, 2)) return;

    size_t offset = 0;
    while (offset + 2 <= length) {
        uint16_t tlv_header = ntohs(*reinterpret_cast<const uint16_t*>(&packet[offset]));
        uint16_t type = (tlv_header >> 9) & 0x7F;
        uint16_t tlv_length = tlv_header & 0x01FF;

        offset += 2;
        if (offset + tlv_length > length) {
            std::cerr << "LLDP TLV truncated" << std::endl;
            break;
        }

        std::cerr << "TLV type:" << type << " length:" << tlv_length << std::endl;
        offset += tlv_length;
    }
}

void dump_stp(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("STP", length, 35)) return;

    uint16_t protocol_id = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint8_t version = packet[2];
    uint8_t bpdu_type = packet[3];

    std::cerr << "protocol_id:0x" << std::hex << protocol_id << std::dec
              << " version:" << static_cast<int>(version)
              << " bpdu_type:" << static_cast<int>(bpdu_type) << std::endl;

    if (length >= 35 && bpdu_type == 0x00) { // Configuration BPDU
        uint16_t flags = packet[4];
        uint64_t root_id = 0;
        memcpy(&root_id, &packet[5], 8);
        uint16_t root_path_cost = ntohl(*reinterpret_cast<const uint32_t*>(&packet[13]));
        uint64_t bridge_id = 0;
        memcpy(&bridge_id, &packet[17], 8);
        uint16_t port_id = ntohs(*reinterpret_cast<const uint16_t*>(&packet[25]));
        uint16_t message_age = ntohs(*reinterpret_cast<const uint16_t*>(&packet[27]));

        std::cerr << "flags:0x" << std::hex << flags << std::dec
                  << " root_id:0x" << std::hex << root_id << std::dec
                  << " root_path_cost:" << root_path_cost
                  << " bridge_id:0x" << std::hex << bridge_id << std::dec
                  << " port_id:" << port_id
                  << " message_age:" << message_age << std::endl;
    }
}
