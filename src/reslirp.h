#ifndef SLIRP_WRAPPER_H
#define SLIRP_WRAPPER_H

#include <unordered_map>
#include <vector>
#include <chrono>
#include <atomic>
#include <poll.h>
#include <libslirp.h>
#include <iostream>

#include "libslirpcompat.h"

using Clock = std::chrono::steady_clock;
using TimerID = uint64_t;

enum {
    LOG_NONE = 0,
    LOG_ERROR = 1,
    LOG_WARNING = 2,
    LOG_INFO = 3,
    LOG_DEBUG = 4,
    LOG_LIBSLIRP = 5,
    LOG_TRACE = 6,
};

class SlirpWrapper {
public:
    SlirpWrapper(const SlirpConfig &config, int debug_level = 0, int dump_flags = 0);
    ~SlirpWrapper();
    void run();

private:
    int32_t log_level;
    uint32_t dump_flags;
    Slirp *slirp;
    std::atomic<TimerID> next_timer_id;
    bool running;

    std::unordered_map<slirp_os_socket, int> socket_map;
    std::vector<struct pollfd> pollfds;

    struct TimerData {
        TimerID id;
        uint64_t expiration;
        SlirpTimerCb callback;
        void *opaque;
    };

    std::vector<TimerData> timers;

    int add_poll_socket(slirp_os_socket socket, int events);
    void inline log_message(int level, const std::string &message) {
        if (level <= log_level) {
            std::cerr << message << std::endl;
        }
    }
    void inline log_debug(const std::string &message) {
        log_message(LOG_DEBUG, message);
    }
    void inline log_info(const std::string &message) {
        log_message(LOG_INFO, message);
    }
    void inline log_warning(const std::string &message) {
        log_message(LOG_WARNING, message);
    }
    void inline log_error(const std::string &message) {
        log_message(LOG_ERROR, message);
    }
    void *timer_new(SlirpTimerCb cb, void *cb_opaque);
    void timer_free(TimerID timer_id);
    void timer_mod(TimerID timer_id, int64_t expire_time_ns);
    void register_poll_socket(slirp_os_socket socket);
    void unregister_poll_socket(slirp_os_socket socket);
    int64_t clock_get_ns();
    void init_completed(Slirp *slirp);
    int get_revents(int idx);
    slirp_ssize_t write_stdout(const void *buf, size_t len);
    slirp_ssize_t write_stdout_all(const void *buf, size_t len);
    void dump_packet(const char *msg, const void *buf, size_t len, uint32_t dump_flags);

    static SlirpCb callbacks;

    // Friend functions as callbacks
    friend int add_poll_socket_cb(slirp_os_socket socket, int events, void *opaque);
    friend void guest_error_cb(const char *msg, void *opaque);
    friend void *timer_new_cb(SlirpTimerCb cb, void *cb_opaque, void *opaque);
    friend void timer_free_cb(void *timer_id_ptr, void *opaque);
    friend void timer_mod_cb(void *timer_id_ptr, int64_t expire_time_ms, void *opaque);
    friend void register_poll_socket_cb(slirp_os_socket socket, void *opaque);
    friend void unregister_poll_socket_cb(slirp_os_socket socket, void *opaque);
    friend int64_t clock_get_ns_cb(void *opaque);
    friend void notify_cb(void *opaque);
    friend void init_completed_cb(Slirp *slirp, void *opaque);
    friend int get_revents_cb(int idx, void *opaque);
    friend slirp_ssize_t write_stdout_cb(const void *buf, size_t len, void *opaque);
};

#endif // SLIRP_WRAPPER_H
