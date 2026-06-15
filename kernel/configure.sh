#!/usr/bin/env sh
# ─────────────────────────────────────────────────────────────────────────────
# HawkGate — kernel/configure.sh
# ─────────────────────────────────────────────────────────────────────────────

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MAKEFILE_PATH="$SCRIPT_DIR/Makefile"

# ── file name defaults ────────────────────────────────────────────────────────
BPF_SRC=${BPF_SRC:-hg_tc.bpf.c}
BPF_OBJ=${BPF_OBJ:-hg_tc.bpf.o}
BPF_SKEL=${BPF_SKEL:-hg_tc.skel.h}
USER_SRC=${USER_SRC:-hg_control.c}
USER_CLI=${USER_CLI:-hg_cli.c}
TARGET=${TARGET:-hgctl}

# ── tool defaults ─────────────────────────────────────────────────────────────
CLANG=${CLANG:-clang}
GCC=${GCC:-gcc}
BPFTOOL=${BPFTOOL:-bpftool}
MAKE_BIN=${MAKE_BIN:-make}

# ── flag defaults ─────────────────────────────────────────────────────────────
BPF_BASE_FLAGS=${BPF_BASE_FLAGS:--O2 -g -target bpf}

# ── required headers ─────────────────────────────────────────────────────────
VMLINUX_HEADER=${VMLINUX_HEADER:-vmlinux.h}

# ─────────────────────────────────────────────────────────────────────────────
# Colours  (disable if not a terminal)
# ─────────────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_GREEN='\033[0;32m'
    C_YELLOW='\033[0;33m'
    C_RED='\033[0;31m'
    C_CYAN='\033[0;36m'
    C_DIM='\033[2m'
else
    C_RESET='' C_BOLD='' C_GREEN='' C_YELLOW='' C_RED='' C_CYAN='' C_DIM=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# Logging helpers
# ─────────────────────────────────────────────────────────────────────────────
section() { printf "\n${C_BOLD}${C_CYAN}◆  %s${C_RESET}\n" "$1"; }
ok()      { printf "  ${C_GREEN}✔${C_RESET}  %s\n" "$1"; }
warn()    { printf "  ${C_YELLOW}⚠${C_RESET}  %s\n" "$1"; }
info()    { printf "  ${C_DIM}·${C_RESET}  %s\n" "$1"; }
fail()    { printf "\n  ${C_RED}✘  error:${C_RESET} %s\n\n" "$1" >&2; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Tool + file checkers
# ─────────────────────────────────────────────────────────────────────────────
check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command not found: ${C_BOLD}$1${C_RESET}\n        Install it and re-run configure.sh"
    fi
    ok "$1  ${C_DIM}$(command -v "$1")${C_RESET}"
}

check_file() {
    if [ ! -f "$SCRIPT_DIR/$1" ]; then
        fail "required source file not found: ${C_BOLD}$1${C_RESET}"
    fi
    ok "$1"
}

pkg_has() {
    command -v pkg-config >/dev/null 2>&1 && pkg-config --exists "$1" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
# vmlinux.h handler — generate or let user supply path
# ─────────────────────────────────────────────────────────────────────────────
handle_vmlinux() {
    if [ -f "$SCRIPT_DIR/$VMLINUX_HEADER" ]; then
        ok "$VMLINUX_HEADER  ${C_DIM}(already present)${C_RESET}"
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
            if ! "$BPFTOOL" btf dump file "$BTF_SRC" format c > "$SCRIPT_DIR/$VMLINUX_HEADER"; then
                fail "bpftool failed to generate vmlinux.h"
            fi
            ok "vmlinux.h generated  ${C_DIM}($(wc -l < "$SCRIPT_DIR/$VMLINUX_HEADER") lines)${C_RESET}"
            ;;
        2)
            printf "  Path to vmlinux.h: "
            read -r vmlinux_path
            vmlinux_path=$(eval echo "$vmlinux_path")   # expand ~ etc.
            if [ ! -f "$vmlinux_path" ]; then
                fail "file not found: $vmlinux_path"
            fi
            cp "$vmlinux_path" "$SCRIPT_DIR/$VMLINUX_HEADER"
            ok "vmlinux.h copied from $vmlinux_path"
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
# Checks
# ─────────────────────────────────────────────────────────────────────────────
section "Build tools"
check_cmd "$CLANG"
check_cmd "$GCC"
check_cmd "$BPFTOOL"
check_cmd "$MAKE_BIN"

section "Kernel version"
KVER=$(uname -r)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 13 ]; }; then
    fail "kernel $KVER is too old\n        HawkGate requires Linux ≥ 5.13  (bpf_skb_set_tstamp)"
fi
ok "Linux $KVER"

section "Source files"
check_file "$BPF_SRC"
check_file "$USER_SRC"
check_file "$USER_CLI"
check_file "hg_tc.bpf.h"
check_file "hg_common.h"
check_file "hg_user.h"
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
# Write Makefile
# ─────────────────────────────────────────────────────────────────────────────
section "Writing Makefile"
cat > "$MAKEFILE_PATH" <<MAKE
# ─────────────────────────────────────────────────────────────────────────────
# HawkGate — kernel/Makefile  (auto-generated by configure.sh)
# Regenerate with: ./configure.sh
# ─────────────────────────────────────────────────────────────────────────────

BPF_SRC      ?= $BPF_SRC
BPF_OBJ      ?= $BPF_OBJ
BPF_SKEL     ?= $BPF_SKEL
USER_SRC     ?= $USER_SRC
USER_CLI     ?= $USER_CLI
TARGET       ?= $TARGET

CLANG        ?= $CLANG
GCC          ?= $GCC
BPFTOOL      ?= $BPFTOOL

BPF_FLAGS    ?= $BPF_BASE_FLAGS
USER_CFLAGS  ?= -O2 -g -Wall -Wextra $LIBBPF_CFLAGS
USER_LIBS    ?= $LIBBPF_LIBS

.PHONY: all clean rebuild

all: \$(TARGET)

\$(BPF_OBJ): \$(BPF_SRC) hg_tc.bpf.h hg_common.h
	\$(CLANG) \$(BPF_FLAGS) -c \$< -o \$@

\$(BPF_SKEL): \$(BPF_OBJ)
	\$(BPFTOOL) gen skeleton \$< > \$@

\$(TARGET): \$(USER_CLI) \$(USER_SRC) \$(BPF_SKEL) hg_user.h hg_common.h
	\$(GCC) \$(USER_CFLAGS) \$(USER_CLI) \$(USER_SRC) -o \$@ \$(USER_LIBS)

rebuild: clean all

clean:
	rm -f \$(BPF_OBJ) \$(BPF_SKEL) \$(TARGET)
MAKE

ok "Makefile written  ${C_DIM}($MAKEFILE_PATH)${C_RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
printf "\n${C_BOLD}${C_GREEN}  ✔  Configuration complete${C_RESET}\n\n"
printf "  ${C_BOLD}Next steps:${C_RESET}\n"
printf "    ${C_CYAN}make${C_RESET}               build hgctl\n"
printf "    ${C_CYAN}make rebuild${C_RESET}       clean build from scratch\n"
printf "    ${C_CYAN}sudo ./hgctl start -i br0${C_RESET}\n\n"
