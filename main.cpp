#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <getopt.h>
#include "reslirp.h"

int main(int argc, char** argv) {
    SlirpConfig config = {
        .version = SLIRP_CONFIG_VERSION_MAX,
        .restricted = 0,
        .in_enabled = true,
        .vnetwork = { .s_addr = inet_addr("10.0.2.0") },
        .vnetmask = { .s_addr = inet_addr("255.255.255.0") },
        .vhost = { .s_addr = inet_addr("10.0.2.2") },
        .in6_enabled = false,
        .vhostname = "slirp",
        .vdhcp_start = { .s_addr = inet_addr("10.0.2.20") },
        .vnameserver = { .s_addr = inet_addr("10.0.2.3") },
        .if_mtu = 1500,
        .if_mru = 1500,
        .disable_dns = false,
        .disable_dhcp = false,
    };

    static struct option long_options[] = {
        {"vnetwork", required_argument, 0, 'n'},
        {"vnetmask", required_argument, 0, 'm'},
        {"vhost", required_argument, 0, 'h'},
        {"vdhcp_start", required_argument, 0, 'd'},
        {"vnameserver", required_argument, 0, 's'},
        {"if_mtu", required_argument, 0, 't'},
        {"if_mru", required_argument, 0, 'r'},
        {"disable_dns", no_argument, 0, 0},
        {"disable_dhcp", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "n:m:h:d:s:t:r:", long_options, &option_index)) != -1) {
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
            case 'd':
                config.vdhcp_start.s_addr = inet_addr(optarg);
                break;
            case 's':
                config.vnameserver.s_addr = inet_addr(optarg);
                break;
            case 't':
                config.if_mtu = std::atoi(optarg);
                break;
            case 'r':
                config.if_mru = std::atoi(optarg);
                break;
            case 0:
                if (std::string(long_options[option_index].name) == "disable_dns") {
                    config.disable_dns = true;
                } else if (std::string(long_options[option_index].name) == "disable_dhcp") {
                    config.disable_dhcp = true;
                }
                break;
            default:
                std::cerr << "Invalid option" << std::endl;
                return EXIT_FAILURE;
        }
    }

    try {
        SlirpWrapper wrapper(config);
        std::cout << "Starting event loop" << std::endl;
        wrapper.run();
        std::cout << "Exiting" << std::endl;
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
