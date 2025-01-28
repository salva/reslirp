#ifndef FLAGSDUMP_H
#define FLAGSDUMP_H

enum DumpMode {
    DUMP_NONE = 0,
    DUMP_ETHER = 1 << 0,
    DUMP_IPV4 = 1 << 1,
    DUMP_IPV6 = 1 << 2,
    DUMP_DHCP = 1 << 3,
    DUMP_DNS = 1 << 4
};

#endif // FLAGSDUMP_H
