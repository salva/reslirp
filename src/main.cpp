#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <getopt.h>
#include <set>
#include <string>
#include <unordered_map>
#include <netdb.h>
#include <unistd.h>
#include "reslirp.h"
#include "flagsdump.h"

void print_help() {
    std::cout << "Usage: [OPTIONS]\n"
              << "Options:\n"
              << "  -n, --vnetwork         Set the virtual network address\n"
              << "  -m, --vnetmask         Set the virtual network mask\n"
              << "  -h, --vhost            Set the virtual host address\n"
              << "  -D, --dump             Set dump flags (ether, ip, ipv4, ipv6, dhcp, dns)\n"
              << "  -s, --vnameserver      Set the nameserver address\n"
              << "  -t, --if-mtu           Set interface MTU\n"
              << "  -r, --if-mru           Set interface MRU\n"
              << "  -d, --debug            Increase debug level (up to 4)\n"
              << "      --disable-dns      Disable DNS\n"
              << "      --disable-dhcp     Disable DHCP\n"
              << "      --restricted       Enable restricted mode\n"
              << "      --disable-host-loopback Disable host loopback\n"
              << "      --enable-emu       Enable emulation\n"
              << "      --vhostname        Set virtual hostname\n"
              << "      --tftp-server-name Set TFTP server name\n"
              << "      --tftp-path        Set TFTP path\n"
              << "      --bootfile         Set bootfile\n"
              << "      --vnameserver6     Set the IPv6 nameserver address\n"
              << "      --vdnssearch       Set DNS search domains\n"
              << "      --vdomainname      Set domain name\n"
              << "      --mfr-id           Set manufacturer ID\n"
              << "      --oob-eth-addr     Set out-of-band Ethernet address\n"
              << "      --reverse          Connect to the specified host:port for tunneling\n"
              << "  -?, --help             Print this help message\n";
}

int parse_dump_flags(const char* flags) {
    int dump_flags = DUMP_NONE;
    std::string flagString(flags);
    size_t start = 0;
    size_t end;

    std::unordered_map<std::string, int> flagMap = {
        {"ether", DUMP_ETHER},
        {"ipv4", DUMP_IPV4},
        {"ipv6", DUMP_IPV6},
        {"dhcp", DUMP_DHCP},
        {"dns", DUMP_DNS},
        {"ip", DUMP_IPV4 | DUMP_IPV6},
        {"all", -1}
    };

    do {
        end = flagString.find(',', start);
        std::string flag = flagString.substr(start, end - start);
        auto it = flagMap.find(flag);
        if (it != flagMap.end()) {
            dump_flags |= it->second;
        }
        else {
            std::cerr << "Invalid dump flag: " << flag << std::endl;
        }
        start = end + 1;
    } while (end != std::string::npos);

    return dump_flags;
}

int connect_to_host(const std::string &host, int port) {
    struct sockaddr_in server_addr;
    struct hostent *he;

    if ((he = gethostbyname(host.c_str())) == nullptr) {
        std::cerr << "gethostbyname() error" << std::endl;
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    std::memcpy(&server_addr.sin_addr, he->h_addr, he->h_length);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int main(int argc, char **argv) {
    const char *defaultDnsSearch[] = {nullptr};
    int log_level = LOG_WARNING;
    int dump_flags = DUMP_NONE;
    int in_fd = 0;
    int out_fd = 1;

    SlirpConfig config = {
        .version = SLIRP_REQUIRED_VERSION,
        .restricted = 0,
        .in_enabled = true,
        .vnetwork = {.s_addr = inet_addr("10.0.2.0")},
        .vnetmask = {.s_addr = inet_addr("255.255.255.0")},
        .vhost = {.s_addr = inet_addr("10.0.2.2")},
        .in6_enabled = false,
        .vprefix_addr6 = IN6ADDR_ANY_INIT,
        .vprefix_len = 0,
        .vhost6 = IN6ADDR_ANY_INIT,
        .vhostname = "reslirp",
        .tftp_server_name = nullptr,
        .tftp_path = nullptr,
        .bootfile = nullptr,
        .vdhcp_start = {.s_addr = inet_addr("10.0.2.20")},
        .vnameserver = {.s_addr = inet_addr("10.0.2.3")},
        .vnameserver6 = IN6ADDR_ANY_INIT,
        .vdnssearch = defaultDnsSearch,
        .vdomainname = nullptr,
        .if_mtu = 1500,
        .if_mru = 1500,
        .disable_host_loopback = false,
        .enable_emu = false,
        .outbound_addr = nullptr,
        .outbound_addr6 = nullptr,
        .disable_dns = false,
        .disable_dhcp = false,
        .mfr_id = 0,
        .oob_eth_addr = {0}
    };

    static struct option long_options[] = {
        {"vnetwork", required_argument, nullptr, 'n'},
        {"vnetmask", required_argument, nullptr, 'm'},
        {"vhost", required_argument, nullptr, 'h'},
        {"vdhcp-start", required_argument, nullptr, 'D'},
        {"vnameserver", required_argument, nullptr, 's'},
        {"dump", required_argument, nullptr, 'D'},
        {"if-mtu", required_argument, nullptr, 't'},
        {"if-mru", required_argument, nullptr, 'r'},
        {"debug", no_argument, nullptr, 'd'},
        {"disable-dns", no_argument, nullptr, 1},
        {"disable-dhcp", no_argument, nullptr, 2},
        {"restricted", no_argument, nullptr, 3},
        {"disable-host-loopback", no_argument, nullptr, 4},
        {"enable-emu", no_argument, nullptr, 5},
        {"vhostname", required_argument, nullptr, 6},
        {"tftp-server-name", required_argument, nullptr, 7},
        {"tftp-path", required_argument, nullptr, 8},
        {"bootfile", required_argument, nullptr, 9},
        {"vnameserver6", required_argument, nullptr, 10},
        {"vdnssearch", required_argument, nullptr, 11},
        {"vdomainname", required_argument, nullptr, 12},
        {"mfr-id", required_argument, nullptr, 13},
        {"oob-eth-addr", required_argument, nullptr, 14},
        {"quiet",no_argument, nullptr, 'q'},
        {"reverse", required_argument, nullptr, 15},
        {"help", no_argument, nullptr, '?'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "n:m:h:D:s:t:r:d?", long_options, &option_index)) != -1) {
        switch (c) {
            case 'n':
                config.vnetwork.s_addr = inet_addr(optarg);
                break;
            case 'm':
                config.vnetmask.s_addr = inet_addr(optarg);
                break;
            case 'h':
                config.vhost.s_addr = inet_addr(optarg);
                break;
            case 'D': {
                dump_flags |= parse_dump_flags(optarg);
                break;
            }
            case 's':
                config.vnameserver.s_addr = inet_addr(optarg);
                break;
            case 't':
                config.if_mtu = std::atoi(optarg);
                break;
            case 'r':
                config.if_mru = std::atoi(optarg);
                break;
            case 'd':
                if (log_level < LOG_DEBUG) {
                    ++log_level;
                }
                break;
            case 'q':
                if (log_level > LOG_WARNING) {
                    log_level -= LOG_WARNING;
                }
                else {
                    log_level = 0;
                }
                break;
            case '?':
                print_help();
                return EXIT_SUCCESS;
            case 1:
                config.disable_dns = true;
                break;
            case 2:
                config.disable_dhcp = true;
                break;
            case 3:
                config.restricted = 1;
                break;
            case 4:
                config.disable_host_loopback = true;
                break;
            case 5:
                config.enable_emu = true;
                break;
            case 6:
                config.vhostname = optarg;
                break;
            case 7:
                config.tftp_server_name = optarg;
                break;
            case 8:
                config.tftp_path = optarg;
                break;
            case 9:
                config.bootfile = optarg;
                break;
            case 10:
                inet_pton(AF_INET6, optarg, &config.vnameserver6);
                break;
            case 11:
                config.vdnssearch = new const char*[]{optarg, nullptr};
                break;
            case 12:
                config.vdomainname = optarg;
                break;
            case 13:
                config.mfr_id = std::strtoul(optarg, nullptr, 10);
                break;
            case 14:
                std::sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &config.oob_eth_addr[0], &config.oob_eth_addr[1],
                    &config.oob_eth_addr[2], &config.oob_eth_addr[3],
                    &config.oob_eth_addr[4], &config.oob_eth_addr[5]);
                break;
            case 15: {
                std::string reverse_arg(optarg);
                size_t colon_pos = reverse_arg.find(':');
                if (colon_pos == std::string::npos) {
                    std::cerr << "Invalid --reverse argument format. Use host:port." << std::endl;
                    return EXIT_FAILURE;
                }
                std::string host = reverse_arg.substr(0, colon_pos);
                int port = std::stoi(reverse_arg.substr(colon_pos + 1));

                in_fd = connect_to_host(host, port);
                if (in_fd < 0) {
                    return EXIT_FAILURE;
                }
                out_fd = in_fd; // Use the same socket for output
                break;
            }
            default:
                std::cerr << "Invalid option. Use --help for usage information." << std::endl;
                return EXIT_FAILURE;
        }
    }

    // std::cerr << "Debug level set to " << log_level << std::endl;
    // std::cerr << "Dump mode set to " << dump_flags << std::endl;

    try {
        SlirpWrapper wrapper(config, in_fd, out_fd, log_level, dump_flags);
        wrapper.run();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
