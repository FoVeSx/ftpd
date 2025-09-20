# Fuzzing the FTP command parser

This scaffold builds a **libFuzzer** target for the FTP daemon implemented in
`ftpd.c`.  The entry-point is the high-level `parser()` routine that handles
every control-channel command sent by an unauthenticated client.

## Quick start

```bash
# From the repository root
bash fuzz/build.sh           # creates fuzz/out/ftp_cmd_parser_fuzz

# Run the fuzzer with an (optional) initial corpus
mkdir -p fuzz/corpus/ftp_cmd_parser
fuzz/out/ftp_cmd_parser_fuzz \
    -artifact_prefix=fuzz/artifacts/ \
    fuzz/corpus/ftp_cmd_parser
```

The binary is sanitised with **ASan** and links the in-process libFuzzer
runtime.  Crashes and leaks will be reported immediately.

## Implementation details

* `fuzz/ftp_cmd_parser_fuzz.cc` provides a replacement `sfgets()` that delivers
  exactly one command taken from the fuzzer input and then signals EOF.  This
  keeps the daemon logic intact without blocking on `select()` / `read()`.
* The original `exit()` calls are redirected to a no-op stub via
  `-Dexit=ftp_exit_stub` so that fatal error paths do not terminate the fuzz
  run.
* The entire project is tiny, therefore `build.sh` compiles the three C source
  files directly with Clang instead of invoking the existing `Makefile`.

## Corpus & seeds

If present, the fuzzer automatically reads input from
`fuzz/corpus/ftp_cmd_parser/`.  Place a few realistic FTP commands there (one
per file, newline-terminated) to give the mutation engine a head-start.

