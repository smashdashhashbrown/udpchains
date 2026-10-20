# udpchains -- Makefile
#
# NFR-01: builds with make plus a C compiler.  No third-party dependencies, no
# downloads, no generated build system.
# NFR-06: -Wall -Wextra -Werror from the first commit.

CC      ?= cc
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
LIBDIR  ?= $(PREFIX)/lib
MANDIR  ?= $(PREFIX)/share/man/man1

VERSION := 0.1.0

WARNINGS := -Wall -Wextra -Werror \
            -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes \
            -Wmissing-prototypes -Wwrite-strings -Wno-unused-parameter

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -fPIC $(WARNINGS) \
           -DUDPCHAINS_VERSION=\"$(VERSION)\" \
           -DUDPCHAINS_LIBDIR=\"$(LIBDIR)\"
LDFLAGS ?=

# NFR-01a / D-09: the close_range hook needs glibc >= 2.34.  Omitting it is a
# deliberate act, not a silent degradation -- src/compat.h fails the build
# otherwise.
ifdef GLIBC_NO_CLOSE_RANGE
CFLAGS += -DUDPCHAINS_NO_CLOSE_RANGE=1
endif

# Sanitiser builds for TST-08.  Kept as separate goals so the shipped shim is
# never accidentally instrumented.
#
# See tests/run_sanitizers.sh for why an ASan run needs care about which library
# gets read(), recv() and recvfrom(): the sanitiser intercepts them too, and if
# it wins, the shim's receive hooks never run and the matrix reports the very
# defect it exists to detect.
ifdef ASAN
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer -O1
LDFLAGS += -fsanitize=address,undefined
endif
ifdef TSAN
CFLAGS  += -fsanitize=thread -fno-omit-frame-pointer -O1
LDFLAGS += -fsanitize=thread
endif

# D-35 / L7: hardening, and an export list of hooks only.  Kept apart from
# CFLAGS so that a CFLAGS given on the command line -- a distribution's own
# flags, say -- does not silently drop it.
#
#   -fvisibility=hidden   nothing the shim defines is exported unless marked;
#                         hooks.c and dnshooks.c mark their hooks.  Internal
#                         udpc_* functions no longer reach every program's
#                         symbol namespace, and TST-02 checks they do not.
#   stack protector, full RELRO, immediate binding: the usual set for a
#                         library loaded into programs it did not write.
#   _FORTIFY_SOURCE=2     only where it is valid: glibc warns without
#                         optimisation, -Werror makes that fatal, and it is
#                         redundant under the sanitisers.
HARDEN_CFLAGS  := -fvisibility=hidden -fstack-protector-strong
HARDEN_LDFLAGS := -Wl,-z,relro -Wl,-z,now
ifeq ($(findstring -O0,$(CFLAGS))$(ASAN)$(TSAN),)
HARDEN_CFLAGS  += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif
CFLAGS  += $(HARDEN_CFLAGS)
LDFLAGS += $(HARDEN_LDFLAGS)

SRCDIR  := src
OBJDIR  := build
TESTDIR := tests

# Everything except the wrapper's own main() belongs to the shim.
SHIM_SRCS    := $(filter-out $(SRCDIR)/wrapper.c,$(wildcard $(SRCDIR)/*.c))
SHIM_OBJS    := $(SHIM_SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# The wrapper links only the pieces it needs: no hooks, no fd table.
WRAPPER_SRCS := $(SRCDIR)/wrapper.c $(SRCDIR)/config.c $(SRCDIR)/log.c \
                $(SRCDIR)/addr.c
WRAPPER_OBJS := $(WRAPPER_SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

SHIM    := libudpchains.so
WRAPPER := udpchains

# Test fixtures (D-06) and test programs.  Test-only: never linked into the
# shipped shim.
FIXTURES := $(OBJDIR)/socks5d $(OBJDIR)/udpecho $(OBJDIR)/dnsd
TESTS    := $(OBJDIR)/test_config $(OBJDIR)/test_socks5 $(OBJDIR)/test_addr \
            $(OBJDIR)/test_matrix $(OBJDIR)/test_fidelity \
            $(OBJDIR)/test_lifecycle $(OBJDIR)/test_thread \
            $(OBJDIR)/leakclient $(OBJDIR)/test_faults \
            $(OBJDIR)/test_fdtable_mt $(OBJDIR)/test_portswitch \
            $(OBJDIR)/bench_latency $(OBJDIR)/test_dns \
            $(OBJDIR)/test_resolve

.PHONY: all clean test check install uninstall fixtures tests interop compare

all: $(SHIM) $(WRAPPER)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

# Objects depend on the Makefile itself: VERSION and the sanitiser flags live
# in CFLAGS, so without this a version bump or a switch to ASAN=1 silently
# reuses objects built with the old settings.  `make` then reports the previous
# version, which is exactly the sort of thing that ships.
$(OBJDIR)/%.o: $(SRCDIR)/%.c Makefile | $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(SHIM): $(SHIM_OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) -ldl -lpthread

$(WRAPPER): $(WRAPPER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# --- tests -------------------------------------------------------------------

fixtures: $(FIXTURES)

tests: $(TESTS)

$(OBJDIR)/socks5d: $(TESTDIR)/fixtures/socks5d.c | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lpthread

$(OBJDIR)/udpecho: $(TESTDIR)/fixtures/udpecho.c | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(OBJDIR)/dnsd: $(TESTDIR)/fixtures/dnsd.c | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Unit tests link the shim's own objects directly rather than preloading it, so
# they can call internal functions.
UNIT_OBJS := $(OBJDIR)/config.o $(OBJDIR)/log.o $(OBJDIR)/addr.o \
             $(OBJDIR)/socks5.o

$(OBJDIR)/test_config: $(TESTDIR)/test_config.c $(UNIT_OBJS) | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/test_socks5: $(TESTDIR)/test_socks5.c $(UNIT_OBJS) | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/test_addr: $(TESTDIR)/test_addr.c $(UNIT_OBJS) | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $^ $(LDFLAGS)

# The DNS codec is pure, so its unit test links it alone (D-22).
$(OBJDIR)/test_dns: $(TESTDIR)/test_dns.c $(OBJDIR)/dns.o | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $^ $(LDFLAGS)

# Integration tests run as ordinary programs under the preloaded shim.
$(OBJDIR)/test_resolve: $(TESTDIR)/test_resolve.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS) -lresolv -lpthread

$(OBJDIR)/test_matrix: $(TESTDIR)/test_matrix.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS)

$(OBJDIR)/test_fidelity: $(TESTDIR)/test_fidelity.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS)

$(OBJDIR)/test_lifecycle: $(TESTDIR)/test_lifecycle.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS)

$(OBJDIR)/test_thread: $(TESTDIR)/test_thread.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS) -lpthread

# Links the fd table directly rather than preloading the shim, so TSan can
# analyse it: TSan understands C11 atomics but intercepts read/recv/recvfrom,
# which conflicts with LD_PRELOAD interposition (see tests/run_sanitizers.sh).
MT_OBJS := $(OBJDIR)/fdtable.o $(OBJDIR)/assoc.o $(OBJDIR)/socks5.o \
           $(OBJDIR)/addr.o $(OBJDIR)/config.o $(OBJDIR)/log.o \
           $(OBJDIR)/real.o $(OBJDIR)/scratch.o $(OBJDIR)/shim.o

$(OBJDIR)/test_fdtable_mt: $(TESTDIR)/test_fdtable_mt.c $(MT_OBJS) | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $^ $(LDFLAGS) -ldl -lpthread

$(OBJDIR)/test_faults: $(TESTDIR)/test_faults.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS)

$(OBJDIR)/test_portswitch: $(TESTDIR)/test_portswitch.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS)

$(OBJDIR)/leakclient: $(TESTDIR)/leakclient.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS)

$(OBJDIR)/bench_latency: $(TESTDIR)/bench_latency.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ $< $(LDFLAGS)

$(OBJDIR)/interop_probe: $(TESTDIR)/interop/probe.c | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# TST-02 runs first and gates everything else: a missing receive hook must fail
# the build, not merely a test.
check: all
	@$(TESTDIR)/test_symbols.sh $(SHIM)

test: all fixtures tests check
	@$(TESTDIR)/run.sh

# Interop against real third-party proxies (INTEROP-CHECKLIST.md 12).  Needs
# Docker and downloads the proxies' images, so it is opt-in and never part of
# `make test`, which needs only a C compiler (NFR-01).
interop: all fixtures tests $(OBJDIR)/interop_probe
	@$(TESTDIR)/interop/run.sh $(INTEROP_ARGS)

# udpchains beside other tools that proxy a program's UDP (README, "Comparison
# with similar tools").  Needs Docker and Python 3, and builds its own copy of
# udpchains from this tree inside the lab, so it is opt-in like `interop`.
compare:
	@$(TESTDIR)/compare/run.sh $(COMPARE_ARGS)

install: all
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(MANDIR)
	install -m 0755 $(WRAPPER) $(DESTDIR)$(BINDIR)/$(WRAPPER)
	install -m 0644 $(SHIM) $(DESTDIR)$(LIBDIR)/$(SHIM)
	install -m 0644 docs/udpchains.1 $(DESTDIR)$(MANDIR)/udpchains.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(WRAPPER) $(DESTDIR)$(LIBDIR)/$(SHIM) \
	      $(DESTDIR)$(MANDIR)/udpchains.1

clean:
	rm -rf $(OBJDIR) $(SHIM) $(WRAPPER)

-include $(wildcard $(OBJDIR)/*.d)
