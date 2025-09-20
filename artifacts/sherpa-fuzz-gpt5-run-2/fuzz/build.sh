#!/usr/bin/env bash
set -euo pipefail

# Portable build script for local fuzzing. Emits fuzzers into fuzz/out/.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FUZZ_DIR="$ROOT_DIR/fuzz"
OUT_DIR="$FUZZ_DIR/out"
mkdir -p "$OUT_DIR"

have() { command -v "$1" >/dev/null 2>&1; }

# Choose compilers: prefer env, then clang/clang++, then gcc/g++.
CC_BIN="${CC:-}"
CXX_BIN="${CXX:-}"
if [[ -n "${CC_BIN}" ]] && ! have "$CC_BIN"; then CC_BIN=""; fi
if [[ -n "${CXX_BIN}" ]] && ! have "$CXX_BIN"; then CXX_BIN=""; fi
if [[ -z "${CC_BIN}" ]]; then
  if have clang; then CC_BIN=clang; elif have gcc; then CC_BIN=gcc; else echo "No C compiler found" >&2; exit 127; fi
fi
if [[ -z "${CXX_BIN}" ]]; then
  if have clang++; then CXX_BIN=clang++; elif have g++; then CXX_BIN=g++; else echo "No C++ compiler found" >&2; exit 127; fi
fi

# Common flags: debug symbols, sanitizers, and reasonable warnings.
CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -I$ROOT_DIR"
CXXFLAGS="$CFLAGS -std=c++14"

# If using clang++, we can link with built-in libFuzzer. For g++, use a
# standalone driver to provide main() and omit -fsanitize=fuzzer.
USING_CLANG=0
case "$(basename "$CXX_BIN")" in
  clang++|*clang++*) USING_CLANG=1 ;;
esac

if [[ "$USING_CLANG" -eq 1 ]]; then
  LDFLAGS="-fsanitize=address,undefined,fuzzer -Wl,--wrap=exit"
else
  LDFLAGS="-fsanitize=address,undefined -Wl,--wrap=exit"
fi

# Sources in repo
SRC_FTPD="$ROOT_DIR/ftpd.c"
SRC_LS="$ROOT_DIR/ls.c"
SRC_DAEMONS="$ROOT_DIR/daemons.c"
HARNESS="$FUZZ_DIR/ftp_cmd_parser_fuzz.cc"

# Compile object files for the project (rename main to avoid conflict with libFuzzer main)
echo "[+] Compiling project objects with $CC_BIN"
"$CC_BIN" $CFLAGS -Dmain=ftpd_original_main -c "$SRC_FTPD" -o "$OUT_DIR/ftpd.o"
"$CC_BIN" $CFLAGS -c "$SRC_LS" -o "$OUT_DIR/ls.o"
"$CC_BIN" $CFLAGS -c "$SRC_DAEMONS" -o "$OUT_DIR/daemons.o"

# If not using clang/libFuzzer, compile a tiny standalone driver.
EXTRA_OBJS=()
if [[ "$USING_CLANG" -ne 1 ]]; then
  echo "[+] Compiling standalone fuzz driver with $CXX_BIN"
  "$CXX_BIN" $CXXFLAGS -c "$FUZZ_DIR/standalone_fuzz_driver.cc" -o "$OUT_DIR/standalone_fuzz_driver.o"
  EXTRA_OBJS+=("$OUT_DIR/standalone_fuzz_driver.o")
fi

# Build the fuzzer harness
echo "[+] Building fuzzer: ftp_cmd_parser_fuzz"
"$CXX_BIN" $CXXFLAGS "$HARNESS" \
  "$OUT_DIR/ftpd.o" "$OUT_DIR/ls.o" "$OUT_DIR/daemons.o" "${EXTRA_OBJS[@]}" \
  -o "$OUT_DIR/ftp_cmd_parser_fuzz" $LDFLAGS -lcrypt || {
  echo "[-] Link failed; retrying without -lcrypt"
  "$CXX_BIN" $CXXFLAGS "$HARNESS" \
    "$OUT_DIR/ftpd.o" "$OUT_DIR/ls.o" "$OUT_DIR/daemons.o" "${EXTRA_OBJS[@]}" \
    -o "$OUT_DIR/ftp_cmd_parser_fuzz" $LDFLAGS
}

# Optional .options file for libFuzzer
cat > "$OUT_DIR/ftp_cmd_parser_fuzz.options" <<'EOF'
-max_len=1024
-timeout=5
EOF

echo "[+] Done. Binaries in $OUT_DIR"
