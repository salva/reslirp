#ifndef LIBSLIRPCOMPAT_H
#define LIBSLIRPCOMPAT_H

#if SLIRP_CONFIG_VERSION_MAX < 6
#define SLIRP_REQUIRED_VERSION 5

typedef int slirp_os_socket;

static inline void slirp_set_debug(int) {}
static inline void slirp_pollfds_fill_socket(Slirp *slirp, uint32_t *timeout,
                                             SlirpAddPollCb add_poll, void *opaque) {
    return slirp_pollfds_fill(slirp, timeout, add_poll, opaque);
}

#else
#define SLIRP_REQUIRED_VERSION 6
#endif




#endif // LIBSLIRPCOMPAT_H
