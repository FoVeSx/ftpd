#!/usr/bin/env bash
# Build script for local fuzzing.
#
# This script is intentionally self-contained and avoids any interactive
# behaviour so that CI systems or the user can simply run:
#
#     bash fuzz/build.sh
#
# The result is one or more libFuzzer executables in `fuzz/out/`.

set -eo pipefail

# Detect compilers. Prefer Clang for full libFuzzer support but fall back to
# GCC if Clang is unavailable.  GCC lacks the `-fsanitize=fuzzer` runtime, so
# we drop that flag when using GCC and compile a tiny standalone `main()` that
# forwards to `LLVMFuzzerTestOneInput` (see `ftp_cmd_parser_fuzz.cc`).  This
# is sufficient for build-time verification even though it does not provide a
# fully-featured in-process mutating fuzzer.

if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
    CC=clang
    CXX=clang++
    FUZZ_SAN_FLAGS=(-fsanitize=fuzzer,address)
    EXTRA_DEFINES=()
else
    echo "[!] clang not found – falling back to GCC without libFuzzer runtime" >&2
    CC=gcc
    CXX=g++
    # GCC supports address sanitizer but not the integrated libFuzzer
    # frontend.  We therefore omit `-fsanitize=fuzzer`.
    FUZZ_SAN_FLAGS=(-fsanitize=address)
    # Tell the harness to provide its own `main()` implementation.
    EXTRA_DEFINES=(-DSTANDALONE_FUZZ_MAIN)
fi

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR="$PROJECT_ROOT/fuzz/out"
mkdir -p "$OUT_DIR"

# Construct common compiler flags.  Sanitiser options and extra defines depend
# on the toolchain chosen above.
COMMON_CFLAGS=(
    "${FUZZ_SAN_FLAGS[@]}"
    -g -O1
    -I"$PROJECT_ROOT"
    -Dsfgets=orig_sfgets      # Rename original blocking reader
    -Dexit=ftp_exit_stub      # Prevent daemon from terminating runner
    "${EXTRA_DEFINES[@]}"
)

# Compile core sources into object files.  The code base is very small, so we
# simply list the files explicitly – no need to parse the existing Makefile.
pushd "$PROJECT_ROOT" >/dev/null

# Build object files for the original C sources.  We apply the `sfgets`/`exit`
# renames and additionally rename the daemon's `main` symbol to avoid a clash
# with the fuzzer harness.
for src in ftpd.c ls.c daemons.c; do
    EXTRA_SRC_CFLAGS=( )
    if [[ "$src" == "ftpd.c" ]]; then
        EXTRA_SRC_CFLAGS+=( -Dmain=ftpd_daemon_main )
    fi
    "$CC" "${COMMON_CFLAGS[@]}" "${EXTRA_SRC_CFLAGS[@]}" -c "$src" -o "${src%.c}.o"
done

# Build the fuzzing harness.
# Build the fuzzing harness.  Remove the `sfgets` rename so that our stub
# keeps the original symbol name expected by the daemon.
HARNESS_CFLAGS=( )
for flag in "${COMMON_CFLAGS[@]}"; do
    [[ "$flag" == "-Dsfgets=orig_sfgets" ]] && continue
    HARNESS_CFLAGS+=( "$flag" )
done

"$CXX" "${HARNESS_CFLAGS[@]}" \
    fuzz/ftp_cmd_parser_fuzz.cc \
    ftpd.o ls.o daemons.o \
    -lcrypt \
    -o "$OUT_DIR/ftp_cmd_parser_fuzz"

popd >/dev/null

echo "[+] Built fuzzer: $OUT_DIR/ftp_cmd_parser_fuzz"
