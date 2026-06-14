# ─────────────────────────────────────────────────────────────────────────────
# HawkGate — kernel/Makefile
#
# Build pipeline:
#   1. clang  hg_tc.bpf.c  →  hg_tc.bpf.o      (BPF bytecode)
#   2. bpftool gen skeleton  →  hg_tc.skel.h    (auto-generated, do not edit)
#   3. gcc    hg_control.c + hg_cli.c  →  hgctl (userspace binary)
#
# Quickstart:
#   ./configure.sh          # probe toolchain + write Makefile vars
#   make                    # or make rebuild for a clean build
# ─────────────────────────────────────────────────────────────────────────────

# ── file names ────────────────────────────────────────────────────────────────
BPF_SRC      ?= hg_tc.bpf.c
BPF_OBJ      ?= hg_tc.bpf.o
BPF_SKEL     ?= hg_tc.skel.h
USER_SRC     ?= hg_control.c
USER_CLI     ?= hg_cli.c
TARGET       ?= hgctl

# ── tools ─────────────────────────────────────────────────────────────────────
CLANG        ?= clang
GCC          ?= gcc
BPFTOOL      ?= bpftool

# ── flags ─────────────────────────────────────────────────────────────────────
BPF_FLAGS    ?= -O2 -g -target bpf
USER_CFLAGS  ?= -O2 -g -Wall -Wextra
USER_LIBS    ?= -lbpf -lelf -lz

# ── phony targets ─────────────────────────────────────────────────────────────
.PHONY: all clean rebuild

# ── default target ────────────────────────────────────────────────────────────
all: $(TARGET)

# ── step 1: compile BPF kernel program ───────────────────────────────────────
$(BPF_OBJ): $(BPF_SRC) hg_tc.bpf.h hg_common.h
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

# ── step 2: generate libbpf skeleton ─────────────────────────────────────────
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# ── step 3: compile userspace binary ─────────────────────────────────────────
$(TARGET): $(USER_CLI) $(USER_SRC) $(BPF_SKEL) hg_user.h hg_common.h
	$(GCC) $(USER_CFLAGS) $(USER_CLI) $(USER_SRC) -o $@ $(USER_LIBS)

# ── utility targets ───────────────────────────────────────────────────────────
rebuild: clean all

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(TARGET)
