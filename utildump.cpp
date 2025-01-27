#include <iostream>
#include <iomanip>
#include <cstring>

#include "utildump.h"

// Helper function to start layer and check length
bool dump_start(const std::string& layer, size_t length, size_t expected) {
    std::cerr << layer << " (" << length;
    if (length < expected) {
        std::cerr << " < " << expected << ") packet too short!" << std::endl;
        return false;
    }
    std::cerr << "): ";
    return true;
}

std::string format_mac_address(const uint8_t* mac) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    std::string result = mac_str;
    bool is_multicast = mac[0] & 0x01;
    bool is_local = mac[0] & 0x02;

    if (is_multicast || is_local) {
        result += " (";
        if (is_multicast) {
            result += "multicast";
        }
        if (is_multicast && is_local) {
            result += ", ";
        }
        if (is_local) {
            result += "local";
        }
        result += ")";
    }
    return result;
}

