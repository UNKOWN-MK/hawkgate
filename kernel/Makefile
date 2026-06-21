# ─────────────────────────────────────────────────────────────────────────────
# HawkGate — kernel/Makefile
#
# Build pipeline:
#   1. clang  hg_tc.bpf.c  →  build/hg_tc.bpf.o   (BPF bytecode)
#   2. bpftool gen skeleton  →  build/hg_tc.skel.h  (auto-generated, do not edit)
#   3. gcc    hg_control.c + hg_cli.c  →  build/hgctl
#   4. gcc    hg_reader.c  →  build/hg_reader.o     (linked into hawkgated)
#
# Quickstart:
#   ./configure.sh          # probe toolchain + write Makefile vars
#   make                    # or make rebuild for a clean build
# ─────────────────────────────────────────────────────────────────────────────

BUILD_DIR    ?= build

# ── file names ────────────────────────────────────────────────────────────────
BPF_SRC      ?= hg_tc.bpf.c
BPF_OBJ      ?= $(BUILD_DIR)/hg_tc.bpf.o
BPF_SKEL     ?= $(BUILD_DIR)/hg_tc.skel.h
USER_SRC     ?= hg_control.c
USER_CLI     ?= hg_cli.c
USER_READER  ?= hg_reader.c
READER_OBJ   ?= $(BUILD_DIR)/hg_reader.o
TARGET       ?= $(BUILD_DIR)/hgctl

# ── tools ─────────────────────────────────────────────────────────────────────
CLANG        ?= clang
GCC          ?= gcc
BPFTOOL      ?= bpftool

# ── flags ─────────────────────────────────────────────────────────────────────
BPF_FLAGS    ?= -O2 -g -target bpf
USER_CFLAGS  ?= -O2 -g -Wall -Wextra -I .
USER_LIBS    ?= -lbpf -lelf -lz

# ── phony targets ─────────────────────────────────────────────────────────────
.PHONY: all clean rebuild

# ── default target ────────────────────────────────────────────────────────────
all: $(BUILD_DIR) $(TARGET) $(READER_OBJ)

# ── create build directory ────────────────────────────────────────────────────
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ── step 1: compile BPF kernel program ───────────────────────────────────────
$(BPF_OBJ): $(BPF_SRC) hg_tc.bpf.h hg_common.h | $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

# ── step 2: generate libbpf skeleton ─────────────────────────────────────────
$(BPF_SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

# ── step 3: compile hgctl userspace binary ────────────────────────────────────
$(TARGET): $(USER_CLI) $(USER_SRC) $(USER_READER) $(BPF_SKEL) hg_user.h hg_common.h hg_reader.h | $(BUILD_DIR)
	$(GCC) $(USER_CFLAGS) -I $(BUILD_DIR) $(USER_CLI) $(USER_SRC) $(USER_READER) -o $@ $(USER_LIBS)

# ── step 4: compile hg_reader as standalone object for hawkgated ──────────────
$(READER_OBJ): $(USER_READER) hg_reader.h hg_user.h hg_common.h | $(BUILD_DIR)
	$(GCC) $(USER_CFLAGS) -c $(USER_READER) -o $@

# ── utility targets ───────────────────────────────────────────────────────────
rebuild: clean all

clean:
	rm -rf $(BUILD_DIR)
