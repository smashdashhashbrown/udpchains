/* compat.h — toolchain floor and feature detection.
 *
 * NFR-01a / D-09: the minimum supported glibc is 2.34, set solely by
 * close_range@@GLIBC_2.34.  Every other hooked call is available far earlier.
 * If an older target is required the close_range hook is conditionally compiled
 * out -- deliberately, via UDPCHAINS_NO_CLOSE_RANGE -- rather than the floor
 * being lowered for everything else.
 *
 * The build fails loudly on an unsupported glibc rather than producing a shim
 * with a silently missing hook, which is the FR-I-02 failure mode.
 */
#ifndef UDPCHAINS_COMPAT_H
#define UDPCHAINS_COMPAT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <features.h>

#if !defined(__linux__)
#error "udpchains targets Linux only (NFR-01)."
#endif

#if !defined(__GLIBC__)
#error "udpchains requires glibc (NFR-01). musl and others are not supported."
#endif

#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34)
#define UDPCHAINS_HAVE_CLOSE_RANGE 1
#else
#ifndef UDPCHAINS_NO_CLOSE_RANGE
#error "udpchains requires glibc >= 2.34 for the close_range hook (NFR-01a). \
Rebuild with 'make GLIBC_NO_CLOSE_RANGE=1' to omit that hook deliberately; the \
resulting shim will not track descriptors closed via close_range()."
#endif
#define UDPCHAINS_HAVE_CLOSE_RANGE 0
#endif

#endif /* UDPCHAINS_COMPAT_H */
