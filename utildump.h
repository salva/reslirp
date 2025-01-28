#ifndef UTILDUMP_H
#define UTILDUMP_H

#include <cstdint>
#include <cstddef> // For size_t
#include <string>

#include "flagsdump.h"
#include "appdump.h"

bool dump_start(const std::string& layer, size_t length, size_t expected, bool dump);
std::string format_mac_address(const uint8_t* mac);


#endif // UTILDUMP_H
