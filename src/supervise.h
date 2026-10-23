/* supervise.h -- supervisor mode (FR-SV-*, D-48 to D-53).
 *
 * The wrapper's second way of running a program: instead of preloading the
 * shim, it stays as the program's parent and serves a seccomp filter's user
 * notifications (D-48), so programs that never call libc -- static and Go
 * binaries -- are covered too.  Wrapper-only: never linked into the shim.
 */
#ifndef UDPCHAINS_SUPERVISE_H
#define UDPCHAINS_SUPERVISE_H

#include <stdbool.h>

#include "config.h"

/* True if a kernel release string ("5.15.0-91-generic") is at least
 * major.minor.  Exposed for the unit test. */
bool udpc_kernel_at_least(const char *release, int major, int minor);

/* Runs program (argv as given to it) under the supervisor, carrying its UDP
 * as cfg says, and returns the status the wrapper should exit with.  If the
 * program was killed by a signal, the supervisor dies of the same signal
 * instead of returning.  Before the
 * program runs, refuses -- returning 1, with a diagnostic, and never running it
 * unsupervised (FR-SV-02) -- if the kernel, the filter, or access to the
 * program's descriptors is not there, or if the program would inherit a socket
 * the supervisor cannot carry (D-50, D-53). */
int udpc_supervise(const struct udpc_config *cfg, const char *program, char **argv);

#endif /* UDPCHAINS_SUPERVISE_H */
