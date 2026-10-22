/* test_supervise_unit.c -- the supervisor's pure parts (D-53).
 *
 * The kernel floor is checked from the release string uname() gives, which
 * varies by distribution; this host's own kernel says nothing about the
 * others. */
#include "tap.h"

#include "supervise.h"

int main(void)
{
	TAP_GROUP("D-53: the kernel floor, from uname's release string");
	TAP_OK(udpc_kernel_at_least("5.14.0", 5, 14), "5.14.0 meets 5.14");
	TAP_OK(udpc_kernel_at_least("5.14.0-427.13.1.el9_4.x86_64", 5, 14),
	       "RHEL 9's 5.14 does");
	TAP_OK(udpc_kernel_at_least("5.15.0-91-generic", 5, 14), "Ubuntu 22.04's 5.15 does");
	TAP_OK(udpc_kernel_at_least("6.1.0-18-amd64", 5, 14), "a 6.x does");
	TAP_OK(udpc_kernel_at_least("7.0.0-38-generic", 5, 14), "a 7.x does");
	TAP_OK(!udpc_kernel_at_least("5.13.19", 5, 14), "5.13 does not");
	TAP_OK(!udpc_kernel_at_least("5.10.0-28-amd64", 5, 14), "Debian 11's 5.10 does not");
	TAP_OK(!udpc_kernel_at_least("4.19.0", 5, 14), "4.19 does not");
	TAP_OK(!udpc_kernel_at_least("5", 5, 14), "a release without a minor is refused");
	TAP_OK(!udpc_kernel_at_least("", 5, 14), "nor is an empty one");
	TAP_OK(!udpc_kernel_at_least("garbage", 5, 14), "nor one that is not a number");
	TAP_DONE();
}
