#!/usr/bin/env sh
# HawkGate — configure.sh
# Run from the project root:  ./configure.sh
# ─────────────────────────────────────────────────────────────────────────────

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KERNEL_DIR="$SCRIPT_DIR/kernel"
HAWKGATED_DIR="$SCRIPT_DIR/hawkgated"
KERNEL_MAKEFILE="$KERNEL_DIR/Makefile"
HAWKGATED_MAKEFILE="$HAWKGATED_DIR/Makefile"
ROOT_MAKEFILE="$SCRIPT_DIR/Makefile"

# ── defaults ──────────────────────────────────────────────────────────────────
BPF_SRC=${BPF_SRC:-hg_tc.bpf.c}
USER_SRC=${USER_SRC:-hg_control.c}
USER_CLI=${USER_CLI:-hg_cli.c}
USER_READER=${USER_READER:-hg_reader.c}
VMLINUX_HEADER=${VMLINUX_HEADER:-vmlinux.h}
CLANG=${CLANG:-clang}
GCC=${GCC:-gcc}
GXX=${GXX:-g++}
BPFTOOL=${BPFTOOL:-bpftool}
MAKE_BIN=${MAKE_BIN:-make}
BPF_BASE_FLAGS=${BPF_BASE_FLAGS:--O2 -g -target bpf}

# ── colours (disable when not a terminal) ────────────────────────────────────
if [ -t 1 ]; then
    C_RESET='\033[0m'; C_BOLD='\033[1m'; C_GREEN='\033[0;32m'
    C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_CYAN='\033[0;36m'; C_DIM='\033[2m'
else
    C_RESET=''; C_BOLD=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_CYAN=''; C_DIM=''
fi

section() { printf "\n${C_BOLD}${C_CYAN}◆  %s${C_RESET}\n" "$1"; }
ok()      { printf "  ${C_GREEN}✔${C_RESET}  %s\n" "$1"; }
warn()    { printf "  ${C_YELLOW}⚠${C_RESET}  %s\n" "$1"; }
fail()    { printf "\n  ${C_RED}✘  error:${C_RESET} %s\n\n" "$1" >&2; exit 1; }

check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command not found: ${C_BOLD}$1${C_RESET}\n        Install it and re-run configure.sh"
    fi
    ok "$1  ${C_DIM}$(command -v "$1")${C_RESET}"
}

check_kernel_file() {
    if [ ! -f "$KERNEL_DIR/$1" ]; then
        fail "required kernel source not found: kernel/$1"
    fi
    ok "kernel/$1"
}

pkg_has() {
    command -v pkg-config >/dev/null 2>&1 && pkg-config --exists "$1" 2>/dev/null
}

# ── vmlinux.h handler ────────────────────────────────────────────────────────
handle_vmlinux() {
    if [ -f "$KERNEL_DIR/$VMLINUX_HEADER" ]; then
        ok "kernel/$VMLINUX_HEADER  ${C_DIM}(already present)${C_RESET}"
        return
    fi

    printf "\n  ${C_YELLOW}⚠${C_RESET}  ${C_BOLD}vmlinux.h${C_RESET} not found.\n"
    printf "     This file encodes your kernel's BTF types and must match\n"
    printf "     the running kernel. It is never committed to the repo.\n\n"
    printf "  ${C_BOLD}How would you like to proceed?${C_RESET}\n"
    printf "     ${C_CYAN}1)${C_RESET} Generate from this kernel  ${C_DIM}(bpftool btf dump … format c)${C_RESET}\n"
    printf "     ${C_CYAN}2)${C_RESET} I will provide the path to an existing vmlinux.h\n"
    printf "     ${C_CYAN}q)${C_RESET} Quit and fix manually\n\n"
    printf "  Choice [1/2/q]: "
    read -r choice

    case "$choice" in
        1)
            BTF_SRC="/sys/kernel/btf/vmlinux"
            if [ ! -f "$BTF_SRC" ]; then
                fail "BTF file not found at $BTF_SRC\n        Your kernel may have been built without CONFIG_DEBUG_INFO_BTF=y"
            fi
            printf "  ${C_DIM}·${C_RESET}  Generating vmlinux.h from $BTF_SRC …\n"
            if ! "$BPFTOOL" btf dump file "$BTF_SRC" format c > "$KERNEL_DIR/$VMLINUX_HEADER"; then
                fail "bpftool failed to generate vmlinux.h"
            fi
            ok "kernel/vmlinux.h generated  ${C_DIM}($(wc -l < "$KERNEL_DIR/$VMLINUX_HEADER") lines)${C_RESET}"
            ;;
        2)
            printf "  Path to vmlinux.h: "
            read -r vmlinux_path
            vmlinux_path=$(eval echo "$vmlinux_path")
            if [ ! -f "$vmlinux_path" ]; then
                fail "file not found: $vmlinux_path"
            fi
            cp "$vmlinux_path" "$KERNEL_DIR/$VMLINUX_HEADER"
            ok "kernel/vmlinux.h copied from $vmlinux_path"
            ;;
        q|Q)
            printf "\n  Exiting. To generate manually:\n"
            printf "    bpftool btf dump file /sys/kernel/btf/vmlinux format c > kernel/vmlinux.h\n\n"
            exit 0
            ;;
        *)
            fail "invalid choice '$choice'"
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
printf "\n${C_BOLD}${C_CYAN}"
printf "  ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ████████╗███████╗\n"
printf "  ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝\n"
printf "  ███████║███████║██║ █╗ ██║█████╔╝ ██║  ███╗███████║   ██║   █████╗  \n"
printf "  ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██║   ██║██╔══██║   ██║   ██╔══╝  \n"
printf "  ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗╚██████╔╝██║  ██║   ██║   ███████╗\n"
printf "  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝\n"
printf "${C_RESET}"
printf "  ${C_DIM}eBPF TC captive portal — configure script${C_RESET}\n"

# ─────────────────────────────────────────────────────────────────────────────
# Tool checks
# ─────────────────────────────────────────────────────────────────────────────
section "Kernel build tools"
check_cmd "$CLANG"
check_cmd "$GCC"
check_cmd "$BPFTOOL"
check_cmd "$MAKE_BIN"

section "Daemon build tools"
check_cmd "$GXX"
if ! printf 'int main(){}\n' | "$GXX" -std=c++20 -x c++ - -o /dev/null >/dev/null 2>&1; then
    fail "$GXX does not support C++20 — install g++ >= 10"
fi
ok "C++20 support confirmed"

section "Kernel version"
KVER=$(uname -r)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 13 ]; }; then
    fail "kernel $KVER is too old\n        HawkGate requires Linux ≥ 5.13  (bpf_skb_set_tstamp)"
fi
ok "Linux $KVER"

section "Kernel source files"
check_kernel_file "$BPF_SRC"
check_kernel_file "$USER_SRC"
check_kernel_file "$USER_CLI"
check_kernel_file "$USER_READER"
check_kernel_file "hg_tc.bpf.h"
check_kernel_file "hg_common.h"
check_kernel_file "hg_user.h"
check_kernel_file "hg_reader.h"
handle_vmlinux

section "Libraries  (libbpf / libelf / zlib)"
LIBBPF_CFLAGS=""
LIBBPF_LIBS="-lbpf -lelf -lz"

if pkg_has libbpf; then
    LIBBPF_CFLAGS=$(pkg-config --cflags libbpf)
    LIBBPF_LIBS=$(pkg-config --libs libbpf)
    if pkg_has libelf; then LIBBPF_LIBS="$LIBBPF_LIBS $(pkg-config --libs libelf)"; fi
    if pkg_has zlib;   then LIBBPF_LIBS="$LIBBPF_LIBS $(pkg-config --libs zlib)";
                       else LIBBPF_LIBS="$LIBBPF_LIBS -lz"; fi
    ok "libbpf  ${C_DIM}(via pkg-config)${C_RESET}"
else
    warn "pkg-config entry for libbpf not found — falling back to -lbpf -lelf -lz"
fi

if ! printf '#include <bpf/libbpf.h>\n#include <bpf/bpf.h>\nint main(void){return 0;}\n' | \
    "$GCC" -x c - $LIBBPF_CFLAGS $LIBBPF_LIBS -o /dev/null >/dev/null 2>&1; then
    fail "libbpf headers or link flags are not usable\n\
        Install:  apt install libbpf-dev libelf-dev zlib1g-dev   ${C_DIM}(Debian/Ubuntu)${C_RESET}\n\
                  yum install libbpf-devel elfutils-libelf-devel  ${C_DIM}(RHEL/Fedora)${C_RESET}"
fi
ok "compile + link smoke test"

# ─────────────────────────────────────────────────────────────────────────────
# Write kernel/Makefile
# ─────────────────────────────────────────────────────────────────────────────
section "Writing kernel/Makefile"
cat > "$KERNEL_MAKEFILE" <<MAKE
# ─────────────────────────────────────────────────────────────────────────────
# HawkGate — kernel/Makefile  (auto-generated by configure.sh — do not edit)
# Regenerate with:  ./configure.sh   (from project root)
# ─────────────────────────────────────────────────────────────────────────────

BUILD_DIR    = build

BPF_SRC      = $BPF_SRC
BPF_OBJ      = \$(BUILD_DIR)/hg_tc.bpf.o
BPF_SKEL     = \$(BUILD_DIR)/hg_tc.skel.h
USER_SRC     = $USER_SRC
USER_CLI     = $USER_CLI
USER_READER  = $USER_READER
READER_OBJ   = \$(BUILD_DIR)/hg_reader.o
TARGET       = \$(BUILD_DIR)/hgctl

CLANG        = $CLANG
GCC          = $GCC
BPFTOOL      = $BPFTOOL

BPF_FLAGS    = $BPF_BASE_FLAGS
USER_CFLAGS  = -O2 -g -Wall -Wextra -I . $LIBBPF_CFLAGS
USER_LIBS    = $LIBBPF_LIBS

.PHONY: all clean rebuild

all: \$(BUILD_DIR) \$(TARGET) \$(READER_OBJ)

\$(BUILD_DIR):
	mkdir -p \$(BUILD_DIR)

\$(BPF_OBJ): \$(BPF_SRC) hg_tc.bpf.h hg_common.h | \$(BUILD_DIR)
	\$(CLANG) \$(BPF_FLAGS) -c \$< -o \$@

\$(BPF_SKEL): \$(BPF_OBJ) | \$(BUILD_DIR)
	\$(BPFTOOL) gen skeleton \$< > \$@

\$(TARGET): \$(USER_CLI) \$(USER_SRC) \$(USER_READER) \$(BPF_SKEL) hg_user.h hg_common.h hg_reader.h | \$(BUILD_DIR)
	\$(GCC) \$(USER_CFLAGS) -I \$(BUILD_DIR) \$(USER_CLI) \$(USER_SRC) \$(USER_READER) -o \$@ \$(USER_LIBS)

\$(READER_OBJ): \$(USER_READER) hg_reader.h hg_user.h hg_common.h | \$(BUILD_DIR)
	\$(GCC) \$(USER_CFLAGS) -c \$(USER_READER) -o \$@

rebuild: clean all

clean:
	rm -rf \$(BUILD_DIR)
MAKE
ok "kernel/Makefile  ${C_DIM}($KERNEL_MAKEFILE)${C_RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# Write hawkgated/Makefile
# ─────────────────────────────────────────────────────────────────────────────
section "Writing hawkgated/Makefile"
cat > "$HAWKGATED_MAKEFILE" <<MAKE
# ─────────────────────────────────────────────────────────────────────────────
# HawkGate — hawkgated/Makefile  (auto-generated by configure.sh — do not edit)
# Regenerate with:  ./configure.sh   (from project root)
# ─────────────────────────────────────────────────────────────────────────────

CXX      = $GXX
CXXFLAGS = -std=c++20 -Wall -Wextra -I src -I ../kernel
LDFLAGS  = $LIBBPF_LIBS

BUILD_DIR = build
TARGET    = \$(BUILD_DIR)/hawkgated
READER_O  = ../kernel/build/hg_reader.o

SRCS = src/main.cpp \\
       src/util/hg_log.cpp \\
       src/util/hg_config.cpp \\
       src/bpf/hg_bpf_ctrl.cpp \\
       src/http/hg_parser.cpp \\
       src/http/hg_connection.cpp \\
       src/http/hg_server.cpp \\
       src/portal/hg_router.cpp \\
       src/portal/hg_portal.cpp \\
       src/portal/hg_auth.cpp \\
       src/portal/local_auth.cpp

OBJS = \$(patsubst %.cpp,\$(BUILD_DIR)/%.o,\$(SRCS))

.PHONY: all clean rebuild

all: \$(TARGET)

\$(TARGET): \$(OBJS) \$(READER_O)
	\$(CXX) \$^ -o \$@ \$(LDFLAGS)

\$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p \$(dir \$@)
	\$(CXX) \$(CXXFLAGS) -c \$< -o \$@

rebuild: clean all

clean:
	rm -rf \$(BUILD_DIR)
MAKE
ok "hawkgated/Makefile  ${C_DIM}($HAWKGATED_MAKEFILE)${C_RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# Write root Makefile
# ─────────────────────────────────────────────────────────────────────────────
section "Writing Makefile"
cat > "$ROOT_MAKEFILE" <<MAKE
# ─────────────────────────────────────────────────────────────────────────────
# HawkGate — Makefile  (auto-generated by configure.sh — do not edit)
# Regenerate with:  ./configure.sh
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: all kernel hawkgated clean rebuild install uninstall

all: kernel hawkgated

kernel:
	\$(MAKE) -C kernel

hawkgated: kernel
	\$(MAKE) -C hawkgated

rebuild:
	\$(MAKE) -C kernel clean
	\$(MAKE) -C hawkgated clean
	\$(MAKE) all

clean:
	\$(MAKE) -C kernel clean
	\$(MAKE) -C hawkgated clean

install: all
	install -d /usr/local/bin
	install -d /etc/hawkgate
	install -d /etc/systemd/system
	install -m 755 kernel/build/hgctl           /usr/local/bin/hgctl
	install -m 755 hawkgated/build/hawkgated    /usr/local/bin/hawkgated
	install -m 644 hawkgated/etc/hawkgate/static/login.html   /etc/hawkgate/login.html
	install -m 644 hawkgated/etc/hawkgate/static/success.html /etc/hawkgate/success.html
	@if [ ! -f /etc/hawkgate/hawkgate.conf ]; then \\
	    install -m 644 hawkgated/etc/hawkgate/hawkgate.conf.example /etc/hawkgate/hawkgate.conf; \\
	    echo "  installed default config → /etc/hawkgate/hawkgate.conf"; \\
	else \\
	    echo "  skipped config (already exists) → /etc/hawkgate/hawkgate.conf"; \\
	fi
	install -m 644 hawkgated/etc/hawkgate/hawkgated.service /etc/systemd/system/hawkgated.service
	systemctl daemon-reload
	@echo ""
	@echo "  HawkGate installed. Next steps:"
	@echo "    1. Edit /etc/hawkgate/hawkgate.conf"
	@echo "    2. systemctl enable --now hawkgated"
	@echo ""

uninstall:
	systemctl stop hawkgated 2>/dev/null || true
	systemctl disable hawkgated 2>/dev/null || true
	rm -f /usr/local/bin/hgctl
	rm -f /usr/local/bin/hawkgated
	rm -f /etc/systemd/system/hawkgated.service
	systemctl daemon-reload
	@echo "  Binaries and service removed."
	@echo "  Config and portal pages kept at /etc/hawkgate/ — remove manually if needed."
MAKE