#include <iostream>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <atomic>
#include <poll.h>
#include <unistd.h>
#include <libslirp.h>
#include "reslirp.h"
#include "pktdump.h"

// Callback function prototypes
int add_poll_socket_cb(slirp_os_socket socket, int events, void *opaque);
void guest_error_cb(const char *msg, void *opaque);
void *timer_new_cb(SlirpTimerCb cb, void *cb_opaque, void *opaque);
void timer_free_cb(void *timer_id_ptr, void *opaque);
void timer_mod_cb(void *timer_id_ptr, int64_t expire_time_ms, void *opaque);
void register_poll_socket_cb(slirp_os_socket socket, void *opaque);
void unregister_poll_socket_cb(slirp_os_socket socket, void *opaque);
int64_t clock_get_ns_cb(void *opaque);
void notify_cb(void *opaque);
void init_completed_cb(Slirp *slirp, void *opaque);
int get_revents_cb(int idx, void *opaque);
slirp_ssize_t write_stdout_cb(const void *buf, size_t len, void *opaque);

SlirpWrapper::SlirpWrapper(const SlirpConfig &config, int debug_level, int dump_level) {
    log_debug("Initializing SlirpWrapper.");
    slirp = slirp_new(&config, &callbacks, this);
    if (!slirp) {
        throw std::runtime_error("Failed to initialize Slirp");
    }
    this->debug_level = debug_level;
    this->dump_level = dump_level;
}

SlirpWrapper::~SlirpWrapper() {
    log_debug("Cleaning up SlirpWrapper.");
    if (slirp) {
        slirp_cleanup(slirp);
    }
}

void SlirpWrapper::run() {
    uint32_t pktin_current = 0;
    uint8_t pktin_buf[9010]; // Jumbo frames
    log_debug("Starting event loop.");
    running = true;

    slirp_set_debug(~0);

    while (running) {
        uint32_t timeout = UINT32_MAX;

        while (1) {
            if (timers.empty()) {
                log_debug("No timers.");
                break;
            } else {
                log_debug("Checking timers.");
                std::sort(timers.begin(), timers.end(),
                    [](const TimerData &a, const TimerData &b) { return a.expiration < b.expiration; });
                uint64_t now = clock_get_ns();
                if (timers.front().expiration <= now) {
                    log_debug("Executing timer ID: " + std::to_string(timers.front().id));
                    timers.front().expiration = UINT64_MAX;
                    timers.front().callback(timers.front().opaque);
                } else {
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

        log_debug("Polling for events, timeout set to " + std::to_string(timeout) + "ms.");
        int ret = poll(pollfds.data(), pollfds.size(), timeout);
        log_debug("Polling completed. Return value: " + std::to_string(ret));

        if (ret < 0) {
            log_debug("poll returned an error.");
            perror("poll");
        } else if (ret > 0) {
            log_debug("Processing pollfds.");
            slirp_pollfds_poll(slirp, ret < 0, get_revents_cb, this);

            if (pollfds[0].revents & POLLIN) {
                ssize_t n = read(STDIN_FILENO, pktin_buf + pktin_current, sizeof(pktin_buf) - pktin_current);

                if (n < 0) {
                    log_debug("Error reading from STDIN.");
                } else if (n == 0) {
                    log_debug("EOF on STDIN.");
                    running = false;
                } else {
                    pktin_current += n;
                    log_debug("Read " + std::to_string(n) + " bytes from STDIN, processing packet.");
                    while (1) {
                        if (pktin_current < 2)
                            break;
                        uint32_t pktin_len = ntohs(*(uint16_t *)(pktin_buf));
                        if (pktin_len > 9000) {
                            log_debug("Packet too large: " + std::to_string(pktin_len) + ", aborting!");
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
                            std::memcpy(pktin_buf, pktin_buf + pktin_len + 2, pktin_current - pktin_len - 2);
                            pktin_current -= pktin_len + 2;
                        } else {
                            pktin_current = 0;
                        }
                    }
                }
            }
        } else {
            log_debug("Timeout occurred.");
            log_debug("SLIRP connection info: " + std::string(slirp_connection_info(slirp)));
            log_debug("SLIRP neighbor info: " + std::string(slirp_neighbor_info(slirp)));
        }
    }

    log_debug("Event loop terminated.");
}

int add_poll_socket_cb(slirp_os_socket socket, int events, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("add_poll_socket_cb invoked. Socket: " + std::to_string(socket));
    return self->add_poll_socket(socket, events);
}

int SlirpWrapper::add_poll_socket(slirp_os_socket socket, int events) {
    short unix_events = 0;

    // Map libslirp event constants to unix poll constants
    if (events & SLIRP_POLL_IN) {
        unix_events |= POLLIN;
    }
    if (events & SLIRP_POLL_OUT) {
        unix_events |= POLLOUT;
    }

    int ix = pollfds.size();
    socket_map[socket] = ix;
    pollfds.push_back({socket, unix_events, 0});
    return ix;
}

void SlirpWrapper::log_debug(const std::string &message) {
    if (debug_level) {
        std::cerr << "[DEBUG] " << message << std::endl;
    }
}

void guest_error_cb(const char *msg, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("guest_error_cb invoked. Message: " + std::string(msg));
}

void *timer_new_cb(SlirpTimerCb cb, void *cb_opaque, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("timer_new_cb invoked (cb: " + std::to_string(reinterpret_cast<uintptr_t>(cb)) +
                    ", cb_opaque: " + std::to_string(reinterpret_cast<uintptr_t>(cb_opaque)) + ")");
    return self->timer_new(cb, cb_opaque);
}

void *SlirpWrapper::timer_new(SlirpTimerCb cb, void *cb_opaque) {
    TimerData timer = { next_timer_id++, UINT64_MAX, cb, cb_opaque };
    timers.push_back(timer);
    return reinterpret_cast<void *>(timer.id);
}

void timer_free_cb(void *timer_id_ptr, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    TimerID timer_id = reinterpret_cast<TimerID>(timer_id_ptr);
    self->log_debug("timer_free_cb invoked for timer ID: " + std::to_string(timer_id));
    self->timer_free(timer_id);
}

void SlirpWrapper::timer_free(TimerID timer_id) {
    timers.erase(std::remove_if(timers.begin(), timers.end(),
                                [timer_id](const TimerData &t) { return t.id == timer_id; }),
                 timers.end());
}

void timer_mod_cb(void *timer_id_ptr, int64_t expire_time_ms, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    TimerID timer_id = reinterpret_cast<TimerID>(timer_id_ptr);
    self->log_debug("timer_mod_cb invoked for timer ID: " + std::to_string(timer_id) +
                    ", expire_time_ms: " + std::to_string(expire_time_ms));
    self->timer_mod(timer_id, expire_time_ms * 1000000); // Convert to nanoseconds
}

void SlirpWrapper::timer_mod(TimerID timer_id, int64_t expire_time_ns) {
    auto it = std::find_if(timers.begin(), timers.end(),
                           [timer_id](const TimerData &t) { return t.id == timer_id; });
    if (it != timers.end()) {
        it->expiration = expire_time_ns;
    } else {
        log_debug("Timer ID not found: " + std::to_string(timer_id));
    }
}

void register_poll_socket_cb(slirp_os_socket socket, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("register_poll_socket_cb invoked. Socket: " + std::to_string(socket));
    self->register_poll_socket(socket);
}

void SlirpWrapper::register_poll_socket(slirp_os_socket /* socket */) {
    return;
}

void unregister_poll_socket_cb(slirp_os_socket socket, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("unregister_poll_socket_cb invoked. Socket: " + std::to_string(socket));
    self->unregister_poll_socket(socket);
}

void SlirpWrapper::unregister_poll_socket(slirp_os_socket /* socket */) {
    return;
}

int64_t clock_get_ns_cb(void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    int64_t nanoseconds = self->clock_get_ns();
    self->log_debug("clock_get_ns_cb invoked. Time: " + std::to_string(nanoseconds) + " ns");
    return nanoseconds;
}

int64_t SlirpWrapper::clock_get_ns() {
    auto now = Clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

void notify_cb(void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("notify_cb invoked.");
}

void init_completed_cb(Slirp *slirp, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("init_completed_cb invoked. Slirp instance initialized.");
    self->init_completed(slirp);
}

void SlirpWrapper::init_completed(Slirp */*slirp*/) {
    return;
}

int get_revents_cb(int idx, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("get_poll_events invoked for index: " + std::to_string(idx));

    return self->get_revents(idx);
}

int SlirpWrapper::get_revents(int idx) {
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

slirp_ssize_t write_stdout_cb(const void *buf, size_t len, void *opaque) {
    auto *self = static_cast<SlirpWrapper *>(opaque);
    self->log_debug("write_cb invoked. Length: " + std::to_string(len));
    return self->write_stdout(buf, len);
}

slirp_ssize_t SlirpWrapper::write_stdout(const void *buf, size_t len) {
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

slirp_ssize_t SlirpWrapper::write_stdout_all(const void *buf, size_t len) {
    size_t current = 0;
    while (current < len) {
        slirp_ssize_t n = write(STDOUT_FILENO, ((const uint8_t *)buf) + current, len - current);
        if (n < 0) {
            if (errno == EINTR) continue;
            log_debug("Error writing to STDOUT: " + std::string(strerror(errno)));
            sleep(1);
            continue;
        } else if (n == 0) {
            log_debug("EOF on STDOUT.");
            running = false;
            return 0;
        } else {
            current += n;
        }
    }
    return current;
}

void SlirpWrapper::dump_packet(const char *msg, const void *buf, size_t len, uint32_t dump_mode) {
    if (dump_mode) {
        std::cerr << msg << ":" << std::endl;
        dump_ethernet((uint8_t *)buf, len, dump_mode);
    }
}

SlirpCb SlirpWrapper::callbacks = {
    .send_packet = write_stdout_cb,
    .guest_error = guest_error_cb,
    .clock_get_ns = clock_get_ns_cb,
    .timer_new = timer_new_cb,
    .timer_free = timer_free_cb,
    .timer_mod = timer_mod_cb,
    .register_poll_fd = nullptr,
    .unregister_poll_fd = nullptr,
    .notify = notify_cb,
    .init_completed = init_completed_cb,
    .timer_new_opaque = nullptr,
    .register_poll_socket = register_poll_socket_cb,
    .unregister_poll_socket = unregister_poll_socket_cb,
};
