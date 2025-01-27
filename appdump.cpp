#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h> // For ntohs and inet_ntop
#include <cctype>     // For isprint

#include "utildump.h"
#include "appdump.h"

void dump_dhcp(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("DHCP", length, 240)) return;

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

    if (flags & DUMP_DHCP) {
        if (length < 240) {
            std::cerr << "[DHCP Packet too short for full payload dump]" << std::endl;
            return;
        }

        const uint8_t* options_start = packet + 240;
        size_t options_length = length - 240;

        std::cerr << "Client IP: " << inet_ntoa(*reinterpret_cast<const in_addr*>(&packet[12])) << std::endl;
        std::cerr << "Your IP: " << inet_ntoa(*reinterpret_cast<const in_addr*>(&packet[16])) << std::endl;
        std::cerr << "Server IP: " << inet_ntoa(*reinterpret_cast<const in_addr*>(&packet[20])) << std::endl;
        std::cerr << "Gateway IP: " << inet_ntoa(*reinterpret_cast<const in_addr*>(&packet[24])) << std::endl;

        std::cerr << "Client MAC: ";
        for (int i = 0; i < hlen; ++i) {
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[28 + i]);
            if (i < hlen - 1) std::cerr << ":";
        }
        std::cerr << std::dec << std::endl;

        std::cerr << "Server Name: " << std::string(reinterpret_cast<const char*>(&packet[44]), 64).c_str() << std::endl;
        std::cerr << "File: " << std::string(reinterpret_cast<const char*>(&packet[108]), 128).c_str() << std::endl;

        std::cerr << "Options: " << std::endl;
        const uint8_t* option_ptr = options_start;
        while (option_ptr < options_start + options_length) {
            uint8_t option_type = option_ptr[0];
            uint8_t option_length = option_ptr[1];
            std::cerr << "  Option: " << static_cast<int>(option_type) << " Length: " << static_cast<int>(option_length) << std::endl;

            switch (option_type) {
            case 53: // DHCP Message Type
                std::cerr << "    Message Type: " << static_cast<int>(option_ptr[2]) << std::endl;
                break;
            case 1: // Subnet Mask
                std::cerr << "    Subnet Mask: "
                          << inet_ntoa(*reinterpret_cast<const in_addr*>(&option_ptr[2])) << std::endl;
                break;
            case 3: // Router
                std::cerr << "    Router: "
                          << inet_ntoa(*reinterpret_cast<const in_addr*>(&option_ptr[2])) << std::endl;
                break;
            case 6: // Domain Name Server
                std::cerr << "    DNS: "
                          << inet_ntoa(*reinterpret_cast<const in_addr*>(&option_ptr[2])) << std::endl;
                break;
            default:
                std::cerr << "    Unknown Option" << std::endl;
                break;
            }

            option_ptr += 2 + option_length; // Move to the next option
        }
    }
}

void dump_dns(const uint8_t* packet, size_t length, int flags) {
    if (!dump_start("DNS", length, 12)) return;

    uint16_t transaction_id = ntohs(*reinterpret_cast<const uint16_t*>(&packet[0]));
    uint16_t flags_field = ntohs(*reinterpret_cast<const uint16_t*>(&packet[2]));
    uint16_t questions = ntohs(*reinterpret_cast<const uint16_t*>(&packet[4]));
    uint16_t answers = ntohs(*reinterpret_cast<const uint16_t*>(&packet[6]));

    std::cerr << "id:" << transaction_id << " flags:0x" << std::hex << flags_field << std::dec
              << " qdcount:" << questions << " ancount:" << answers << std::endl;

    if (flags & DUMP_DNS) {
        if (length < 12) {
            std::cerr << "[DNS Packet too short for full payload dump]" << std::endl;
            return;
        }

        const uint8_t* current = packet + 12; // Skip the fixed header part
        size_t remaining_length = length - 12;

        // Dump questions
        for (uint16_t i = 0; i < questions; ++i) {
            if (remaining_length == 0) break;

            std::string question_name;
            while (*current != 0) {
                uint8_t label_length = *current++;
                question_name.append(reinterpret_cast<const char*>(current), label_length);
                question_name.push_back('.');
                current += label_length;
                remaining_length -= (label_length + 1);
            }
            current++; // Skip the null terminator
            remaining_length--;

            if (remaining_length < 4) {
                std::cerr << "[Insufficient length for QTYPE and QCLASS]" << std::endl;
                break;
            }

            uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t*>(current));
            uint16_t qclass = ntohs(*reinterpret_cast<const uint16_t*>(current + 2));
            current += 4; // Skip QTYPE and QCLASS
            remaining_length -= 4;

            std::cerr << "Question " << i + 1 << ": " << question_name << " QTYPE: " << qtype << " QCLASS: " << qclass << std::endl;
        }

        // Dump answers
        for (uint16_t i = 0; i < answers; ++i) {
            if (remaining_length == 0) break;

            std::string answer_name;
            while (*current != 0) {
                uint8_t label_length = *current++;
                answer_name.append(reinterpret_cast<const char*>(current), label_length);
                answer_name.push_back('.');
                current += label_length;
                remaining_length -= (label_length + 1);
            }
            current++; // Skip the null terminator
            remaining_length--;

            if (remaining_length < 10) {
                std::cerr << "[Insufficient length for TYPE, CLASS, TTL, RDLENGTH]" << std::endl;
                break;
            }

            uint16_t ans_type = ntohs(*reinterpret_cast<const uint16_t*>(current));
            uint16_t ans_class = ntohs(*reinterpret_cast<const uint16_t*>(current + 2));
            uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t*>(current + 4));
            uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t*>(current + 8));
            current += 10; // Skip TYPE, CLASS, TTL, and RDLENGTH
            remaining_length -= 10;

            std::cerr << "Answer " << i + 1 << ": " << answer_name << " TYPE: " << ans_type << " CLASS: " << ans_class 
                      << " TTL: " << ttl << " RDLENGTH: " << rdlength << std::endl;

            if (remaining_length < rdlength) {
                std::cerr << "[Insufficient length for RDATA]" << std::endl;
                break;
            }

            // Dump RDATA
            std::cerr << "RDATA: ";
            for (uint16_t j = 0; j < rdlength; ++j) {
                std::cerr << std::to_string(current[j]) << (j < rdlength - 1 ? "." : "");
            }
            std::cerr << std::endl;
            current += rdlength;
            remaining_length -= rdlength;
        }
    }
}
