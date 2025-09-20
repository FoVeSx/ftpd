Local Fuzzing Harness

- Target: `ftpd::parser` via `ftp_cmd_parser_fuzz`
- Harness: `fuzz/ftp_cmd_parser_fuzz.cc` (libFuzzer)

What it does
- Initializes a benign FTP server state (`loggedin=1`, `guest=0`, `type=2`, `wd=/`, `idletime=1`).
- Pipes fuzz input to STDIN so `sfgets()` reads it like real control-connection lines.
- Appends a newline if missing to let `sfgets()` return cleanly.
- Interposes `exit()` using a linker wrap and `longjmp` so fatal paths (EOF/timeout) do not kill the process.

Build
- Requirements: `clang`/`clang++` available locally (no network access needed).
- Run: `bash fuzz/build.sh`
- Output: binaries appear in `fuzz/out/`.

Run
- Example (with a small corpus directory):
  - `./fuzz/out/ftp_cmd_parser_fuzz -runs=0 fuzz/corpus/ftp_cmd_parser_fuzz`

Corpus
- Seed directory: `fuzz/corpus/ftp_cmd_parser_fuzz/`
- Seeds are simple FTP command lines (each ending with `\n`), e.g., `NOOP`, `SYST`, `USER/PASS`, `CWD`, `TYPE`, `SITE idle`, `PORT/EPRT` variants, `PASV/EPSV`, `REST`, `RNFR/RNTO`, `SIZE`, `MDTM`, `DELE`, `LIST` options.

Notes
- The harness links the project sources directly and renames `main` from `ftpd.c` to avoid conflicts with libFuzzer.
- Data-connection commands will fail gracefully with `datafd=0`; no real sockets are required for basic coverage of the parser and dispatch logic.

