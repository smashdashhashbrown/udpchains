/* tap.h -- the smallest test harness that is still useful.
 *
 * No third-party test framework, per NFR-01: the build needs nothing but a C
 * compiler.  Output is TAP-ish so a human and run.sh can both read it.
 */
#ifndef UDPCHAINS_TAP_H
#define UDPCHAINS_TAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tap_count;
static int tap_failed;
static const char *tap_group = "";

#define TAP_GROUP(name) \
	do { \
		tap_group = (name); \
		printf("# %s\n", (name)); \
	} while (0)

#define TAP_OK(cond, ...) \
	do { \
		tap_count++; \
		if (cond) { \
			printf("ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} else { \
			tap_failed++; \
			printf("not ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n#   at %s:%d in %s\n", __FILE__, __LINE__, \
			       tap_group); \
		} \
	} while (0)

#define TAP_EQ_INT(got, want, ...) \
	do { \
		long long g_ = (long long)(got), w_ = (long long)(want); \
		tap_count++; \
		if (g_ == w_) { \
			printf("ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} else { \
			tap_failed++; \
			printf("not ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n#   got %lld, want %lld at %s:%d\n", g_, w_, \
			       __FILE__, __LINE__); \
		} \
	} while (0)

#define TAP_EQ_STR(got, want, ...) \
	do { \
		const char *g_ = (got), *w_ = (want); \
		tap_count++; \
		if (g_ != NULL && w_ != NULL && strcmp(g_, w_) == 0) { \
			printf("ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} else { \
			tap_failed++; \
			printf("not ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n#   got '%s', want '%s' at %s:%d\n", \
			       g_ ? g_ : "(null)", w_ ? w_ : "(null)", __FILE__, \
			       __LINE__); \
		} \
	} while (0)

#define TAP_EQ_MEM(got, want, len, ...) \
	do { \
		tap_count++; \
		if (memcmp((got), (want), (len)) == 0) { \
			printf("ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} else { \
			tap_failed++; \
			printf("not ok %d - ", tap_count); \
			printf(__VA_ARGS__); \
			printf("\n#   %zu bytes differ at %s:%d\n", (size_t)(len), \
			       __FILE__, __LINE__); \
		} \
	} while (0)

#define TAP_DONE() \
	do { \
		printf("1..%d\n", tap_count); \
		if (tap_failed) \
			printf("# FAILED %d of %d\n", tap_failed, tap_count); \
		return tap_failed ? 1 : 0; \
	} while (0)

#endif /* UDPCHAINS_TAP_H */
