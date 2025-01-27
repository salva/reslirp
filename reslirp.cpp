#include <iostream>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <atomic>
#include <poll.h> // Use Unix poll mechanism
#include <unistd.h> // For write()
#include <libslirp.h>

#include "pktdump.h"

using Clock = std::chrono::steady_clock;
using TimerID = uint64_t;

// Class to encapsulate application data and event loop
class SlirpWrapper {
public:
    SlirpWrapper(const SlirpConfig &config) {
        log_debug("Initializing SlirpWrapper.");
        slirp = slirp_new(&config, &callbacks, this);
        if (!slirp) {
            throw std::runtime_error("Failed to initialize Slirp");
        }
    }

    ~SlirpWrapper() {
        log_debug("Cleaning up SlirpWrapper.");
        if (slirp) {
            slirp_cleanup(slirp);
        }
    }

    void run() {
        uint32_t pktin_current = 0;
        uint8_t pktin_buf[9010]; // just in case we get jumbo frames
        log_debug("Starting event loop.");
        running = true;

        slirp_set_debug(~0);

        while (running) {
            uint32_t timeout = UINT32_MAX;

            while (1) {
                if (timers.empty()) {
                    log_debug("No timers.");
                    break;
                }
                else {
                    log_debug("Checking timers.");
                    sort(timers.begin(), timers.end(),
                         [](const TimerData &a, const TimerData &b) { return a.expiration < b.expiration; });
                    uint64_t now = clock_get_ns();
                    if (timers.front().expiration <= now) {
                        log_debug("Executing timer ID: " + std::to_string(timers.front().id));
                        timers.front().expiration = UINT64_MAX;
                        timers.front().callback(timers.front().opaque);
                    }
                    else {
                        uint64_t expiration = timers.front().expiration;
                        if (expiration < UINT64_MAX) {
                            uint64_t timeout64 = (expiration - now) / 1000000;
                            timeout = (uint32_t)((timeout64 < UINT32_MAX) ? timeout64 : UINT32_MAX);
                        }
                        break;
                    }
                }
            }

            log_debug("Updating poll FDs.");
            socket_map.clear();
            pollfds.clear();

            // STDIN goes in the first position
            pollfds.push_back({STDIN_FILENO, POLLIN, 0});

            slirp_pollfds_fill_socket(slirp, &timeout, add_poll_socket_cb, this);

            log_debug("Polling for events, timeout set to " + std::to_string(timeout) + "ms.");;
            int ret = poll(pollfds.data(), pollfds.size(), timeout);
            log_debug("Polling completed. Return value: " + std::to_string(ret));

            int there_was_an_error = ret < 0;
            if (there_was_an_error) {
                log_debug("poll returned an error.");
                perror("poll");
            }
            else if (ret > 0) {
                log_debug("Processing pollfds.");
                slirp_pollfds_poll(slirp, there_was_an_error, get_revents_cb, this);

                if (pollfds[0].revents & POLLIN) {
                    ssize_t n = read(STDIN_FILENO, pktin_buf + pktin_current, sizeof(pktin_buf) - pktin_current);

                    if (n < 0) {
                        log_debug("Error reading from STDIN.");
                    }
                    else if (n == 0) {
                        log_debug("EOF on STDIN.");
                        running = false;
                    }
                    else {
                        pktin_current += n;
                        log_debug("Read " + std::to_string(n) + " bytes from STDIN, processing packet.");
                        while (1) {
                            if (pktin_current < 2)
                                break;
                            // uint32_t pktin_len = ntohl(*(uint32_t*)pktin_buf);
                            uint32_t pktin_len = ntohs(*(uint16_t*)(pktin_buf));
                            if (pktin_len > 9000) {
                                log_debug("Packet too large: " + std::to_string(pktin_len) + ", aborting!");
                                // dump_raw_packet(pktin_buf, pktin_current);
                                pktin_current = 0;
                                running = false;
                                break;
                            }
                            if (pktin_current < pktin_len + 2)
                                break;
                            log_debug("Packet read from STDIN, processing it, len: " + std::to_string(pktin_len));
                            dump_packet("Packet received", pktin_buf + 2, pktin_len, ~0);
                            log_debug("Just before slirp_input");
                            slirp_input(slirp, pktin_buf + 2, pktin_len);
                            log_debug("Packet processed, removing it from buffer.");
                            if (pktin_current > pktin_len + 2) {
                                log_debug("Shifting buffer.");
                                memcpy(pktin_buf, pktin_buf + pktin_len + 2, pktin_current - pktin_len - 2);
                                pktin_current -= pktin_len + 2;
                            }
                            else {
                                pktin_current = 0;
                            }
                        }
                    }
                }
            }
            else {
                log_debug("Timeout occurred.");
                log_debug("SLIRP connection info: " + std::string(slirp_connection_info(slirp)));
                log_debug("SLIRP neighbor info: " + std::string(slirp_neighbor_info(slirp)));
            }
        }

        log_debug("Event loop terminated.");
    }

private:
    bool debug_mode = true; // Enable or disable debugging mode
    uint32_t dump_mode = ~0L;
    Slirp *slirp;
    std::atomic<TimerID> next_timer_id{0};
    bool running = true;

    std::unordered_map<slirp_os_socket, int> socket_map;
    std::vector<struct pollfd> pollfds;

    struct TimerData {
        TimerID id;
        uint64_t expiration;
        SlirpTimerCb callback;
        void *opaque;
    };

    std::vector<TimerData> timers;

    static int add_poll_socket_cb(slirp_os_socket socket, int events, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("add_poll_socket_cb invoked. Socket: " + std::to_string(socket));
        return self->add_poll_socket(socket, events);
    }

    int add_poll_socket(slirp_os_socket socket, int events) {
        int ix = -1;
        if (socket_map.find(socket) == socket_map.end()) {
            ix = pollfds.size();
            socket_map[socket] = ix;
            pollfds.push_back({socket, 0, 0});
        } else {
            ix = socket_map[socket];
        }

        if (events & SLIRP_POLL_IN) pollfds[ix].events |= POLLIN;
        if (events & SLIRP_POLL_OUT) pollfds[ix].events |= POLLOUT;

        return ix;
    }

    void log_debug(const std::string &message) {
        if (debug_mode) {
            std::cerr << "[DEBUG] " << message << std::endl;
        }
    }

    static void guest_error_cb(const char *msg, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("guest_error_cb invoked. Message: " + std::string(msg));
    }

    static void *timer_new_cb(SlirpTimerCb cb, void *cb_opaque, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("timer_new_cb invoked (cb: " + std::to_string(reinterpret_cast<uintptr_t>(cb)) +
                        ", cb_opaque: " + std::to_string(reinterpret_cast<uintptr_t>(cb_opaque)) + ")");
        return self->timer_new(cb, cb_opaque);
    }

    void *timer_new(SlirpTimerCb cb, void *cb_opaque) {
        TimerData timer = {
            .id = next_timer_id++,
            .expiration = UINT64_MAX,
            .callback = cb,
            .opaque = cb_opaque
        };
        timers.push_back(timer);
        return reinterpret_cast<void *>(timer.id);
    }

    static void timer_free_cb(void *timer_id_ptr, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        TimerID timer_id = reinterpret_cast<TimerID>(timer_id_ptr);
        self->log_debug("timer_free_cb invoked for timer ID: " + std::to_string(timer_id));
        return self->timer_free(timer_id);
    }

    void timer_free(TimerID timer_id) {
        timers.erase(std::remove_if(timers.begin(), timers.end(),
                                    [timer_id](const TimerData &t) { return t.id == timer_id; }),
                     timers.end());
    }

    static void timer_mod_cb(void *timer_id_ptr, int64_t expire_time_ms, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        TimerID timer_id = reinterpret_cast<TimerID>(timer_id_ptr);
        self->log_debug("timer_mod_cb invoked for timer ID: " + std::to_string(timer_id) +
                        ", expire_time_ms: " + std::to_string(expire_time_ms));
        return self->timer_mod(timer_id, expire_time_ms * 1000000); // Convert to nanoseconds
    }

    void timer_mod(TimerID timer_id, int64_t expire_time_ns) {
        auto it = std::find_if(timers.begin(), timers.end(),
                               [timer_id](const TimerData &t) { return t.id == timer_id; });
        if (it != timers.end()) {
            it->expiration = expire_time_ns;
        }
        else {
            log_debug("Timer ID not found: " + std::to_string(timer_id));
        }
    }

    static void register_poll_socket_cb(slirp_os_socket socket, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("register_poll_socket_cb invoked. Socket: " + std::to_string(socket));
        return self->register_poll_socket(socket);
    }

    void register_poll_socket(slirp_os_socket socket) {
        return;
    }

    static void unregister_poll_socket_cb(slirp_os_socket socket, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("unregister_poll_socket_cb invoked. Socket: " + std::to_string(socket));
        return self->unregister_poll_socket(socket);
    }

    void unregister_poll_socket(slirp_os_socket socket) {
        return;
    }

    static int64_t clock_get_ns_cb(void *opaque) {
        auto now = Clock::now().time_since_epoch();
        auto *self = static_cast<SlirpWrapper *>(opaque);
        int64_t nanoseconds = self->clock_get_ns();
        self->log_debug("clock_get_ns_cb invoked. Time: " + std::to_string(nanoseconds) + " ns");
        return nanoseconds;
    }

    int64_t clock_get_ns() {
        auto now = Clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    }

    static void notify_cb(void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("notify_cb invoked.");
    }

    static void init_completed_cb(Slirp *slirp, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("init_completed_cb invoked. Slirp instance initialized.");
        self->init_completed(slirp);
    }

    void init_completed(Slirp *slirp) {
        return;
    }

    static int get_revents_cb(int idx, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("get_poll_events invoked for index: " + std::to_string(idx));

        return self->get_revents(idx);
    }

    int get_revents(int idx) {
        if (idx < 0 || (unsigned int)idx >= pollfds.size()) {
            log_debug("Invalid index at get_revents: " + std::to_string(idx));
            return 0;
        }

        int revents = 0;
        if (pollfds[idx].revents & POLLIN)  revents |= SLIRP_POLL_IN;
        if (pollfds[idx].revents & POLLOUT) revents |= SLIRP_POLL_OUT;
        if (pollfds[idx].revents & POLLERR) revents |= SLIRP_POLL_ERR;
        if (pollfds[idx].revents & POLLHUP) revents |= SLIRP_POLL_HUP;
        return revents;
    }

    static slirp_ssize_t write_stdout_cb(const void *buf, size_t len, void *opaque) {
        auto *self = static_cast<SlirpWrapper *>(opaque);
        self->log_debug("write_cb invoked. Length: " + std::to_string(len));
        return self->write_stdout(buf, len);
    }

    slirp_ssize_t write_stdout(const void *buf, size_t len) {
        if (len > 9000) {
            log_debug("Packet too large: " + std::to_string(len) + ", drooping it!");
            return -1;
        }

        dump_packet("Packet sent", buf, len, ~0);

        int16_t lennl = htons((int16_t)len);
        slirp_ssize_t r = write_stdout_all(&lennl, sizeof(lennl));
        if (r <= 0) return r;
        return write_stdout_all(buf, len);
    }

    slirp_ssize_t write_stdout_all(const void *buf, size_t len) {
        size_t current = 0;
        while (current < len) {
            slirp_ssize_t n = write(STDOUT_FILENO, ((const uint8_t *)buf) + current, len - current);
            if (n < 0) {
                if (errno == EINTR) continue;
                log_debug("Error writing to STDOUT: " + std::string(strerror(errno)));
                sleep(1);
                continue;
            }
            else if (n == 0) {
                log_debug("EOF on STDOUT.");
                running = false;
                return 0;
            }
            else {
                current += n;
            }
        }
        return current;
    }

    void dump_packet(const char *msg, const void *buf, size_t len, uint32_t dump_mode) {
        if (dump_mode) {
            std::cerr << msg << ":" << std::endl;
            dump_ethernet((uint8_t *)buf, len, dump_mode);
        }
    }

    static SlirpCb callbacks;
};

SlirpCb SlirpWrapper::callbacks = {
    .send_packet = write_stdout_cb,
    .guest_error = guest_error_cb,
    .clock_get_ns = clock_get_ns_cb,
    .timer_new = timer_new_cb,
    .timer_free = timer_free_cb,
    .timer_mod = timer_mod_cb,
    .notify = notify_cb,
    .init_completed = init_completed_cb,
    .timer_new_opaque = nullptr,
    .register_poll_socket = register_poll_socket_cb,
    .unregister_poll_socket = unregister_poll_socket_cb,
};

int main() {
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
