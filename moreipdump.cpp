#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
#include "utildump.h"
#include "pktdump.h"

void dump_sctp(const uint8_t* packet, size_t length, int /* flags */) {
    if (!dump_start("SCTP", length, 12)) return;

    uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint32_t verification_tag = ntohl(*reinterpret_cast<const uint32_t*>(&packet[4]));
    uint32_t checksum = ntohl(*reinterpret_cast<const uint32_t*>(&packet[8]));

    std::cerr << "src_port:" << src_port << " dst_port:" << dst_port
              << " verification_tag:0x" << std::hex << verification_tag << std::dec
              << " checksum:0x" << std::hex << checksum << std::dec << std::endl;

    size_t offset = 12;
    while (offset + 4 <= length) {
        uint8_t chunk_type = packet[offset];
        uint8_t chunk_flags = packet[offset + 1];
        uint16_t chunk_length = ntohs(*reinterpret_cast<const uint16_t*>(&packet[offset + 2]));

        if (offset + chunk_length > length || chunk_length < 4) {
            std::cerr << "SCTP chunk truncated or invalid length" << std::endl;
            break;
        }

        std::string chunk_type_desc;
        switch (chunk_type) {
            case 0x00: chunk_type_desc = "DATA"; break;
            case 0x01: chunk_type_desc = "INIT"; break;
            case 0x02: chunk_type_desc = "INIT_ACK"; break;
            case 0x03: chunk_type_desc = "SACK"; break;
            case 0x04: chunk_type_desc = "HEARTBEAT"; break;
            case 0x05: chunk_type_desc = "HEARTBEAT_ACK"; break;
            case 0x06: chunk_type_desc = "ABORT"; break;
            case 0x07: chunk_type_desc = "SHUTDOWN"; break;
            case 0x08: chunk_type_desc = "SHUTDOWN_ACK"; break;
            case 0x09: chunk_type_desc = "ERROR"; break;
            case 0x0A: chunk_type_desc = "COOKIE_ECHO"; break;
            case 0x0B: chunk_type_desc = "COOKIE_ACK"; break;
            default: chunk_type_desc = "UNKNOWN"; break;
        }

        std::cerr << "chunk_type:" << static_cast<int>(chunk_type) << " (" << chunk_type_desc << ")"
                  << " chunk_flags:0x" << std::hex << static_cast<int>(chunk_flags) << std::dec
                  << " chunk_length:" << chunk_length << std::endl;

        offset += chunk_length;
    }
}

void dump_l2tp(const uint8_t* packet, size_t length, int /* flags */) {
    if (!dump_start("L2TP", length, 6)) return;

    uint16_t flags_and_version = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t version = flags_and_version & 0x0F;
    bool length_present = flags_and_version & 0x4000;
    bool offset_present = flags_and_version & 0x0800;
    bool priority = flags_and_version & 0x0200;

    uint16_t length_field = length_present ? ntohs(*reinterpret_cast<const uint16_t*>(&packet[2])) : 0;
    uint16_t tunnel_id = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));
    uint16_t session_id = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));

    std::cerr << "flags:0x" << std::hex << (flags_and_version >> 8) << std::dec
              << " (length_present:" << length_present
              << " offset_present:" << offset_present
              << " priority:" << priority << ")"
              << " version:" << version
              << " length:" << length_field
              << " tunnel_id:" << tunnel_id
              << " session_id:" << session_id << std::endl;

    size_t offset = length_present ? 8 : 6;
    if (offset_present) {
        if (offset + 2 > length) {
            std::cerr << "L2TP offset field truncated" << std::endl;
            return;
        }
        uint16_t offset_size = ntohs(*reinterpret_cast<const uint16_t*>(&packet[offset]));
        offset += offset_size;
    }

    if (offset < length) {
        std::cerr << "Payload: " << (length - offset) << " bytes" << std::endl;
    } else {
        std::cerr << "No payload" << std::endl;
    }
}
