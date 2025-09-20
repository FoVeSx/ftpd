ftp_cmd_parser_fuzz

### Overview
This repository implements a small standalone FTP daemon (`ftpd.c`, `ls.c`,
`daemons.c`).  All traffic arrives on the **control channel** as
newline-terminated ASCII commands (e.g. `USER`, `LIST`, `PORT`).  The daemon
does all parsing manually using `scanf`, pointer arithmetic and global state –
ideal conditions for fuzzing.

The targets below were selected because they are the **first code reached by an
unauthenticated network client**, contain substantial branch logic and only
require lightweight stubbing for I/O.  Lower-level helpers (`_read_u32`,
string utilities, etc.) were intentionally skipped in favour of these
higher-level, protocol-aware entrypoints.

### Best initial target
`ftp_cmd_parser_fuzz` → `ftpd.c::parser`

- Runs for **every** control-channel line; highest code coverage per input.
- Self-contained: after a trivial global setup the function loops forever,
  consuming bytes from a buffer (`cmd`).  A harness can copy the fuzzer input
  into `cmd`, set `idletime=0` to skip the `select()` timeout and invoke
  `parser()` once.
- Exercises internal helpers (`doport`, `docwd`, `donlist`, …), amplifying
  coverage while keeping the harness simple.

### Other promising, attacker-reachable parsers

| Rank | API | Why it matters | Init / quirks |
|------|-----|----------------|---------------|
| 2 | `ls.c::donlist` | Parses the argument string for `LIST`/`NLST`, handling dozens of option flags (`-alCRtS…`) and filenames. | Needs `wd` set; may `chdir`, `mmap` passwd caches – stub filesystem calls in harness. |
| 3 | `ftpd.c::doport` | Decodes `PORT`/`EPRT` host & port numbers via `sscanf`; integer math on user-controlled values. | Pure logic; safe to call directly with two 32-bit ints derived from fuzzer bytes. |
| 4 | `ftpd.c::docwd` | Canonicalises user-supplied path for `CWD`/`CDUP`, interacts with `chdir`. | Requires writable `wd[]`; stub `chdir` to avoid filesystem side-effects. |
| 5 | `ftpd.c::sfgets` | Custom line-reader implementing protocol framing and timeout logic. | Provide input via a fake buffer; stub `select`, `read` syscalls. |

### Build notes

* **Build target**: the existing `Makefile` builds a single binary `ftpd`; the
  same object files can be compiled under `clang -fsanitize=fuzzer,address …`.
* **Linkage**: provide a tiny `main()` that initialises globals and forwards
  the fuzzer buffer into the chosen entrypoint.
* **System calls**: replace networking and heavy filesystem calls with no-op
  stubs or `assert(0 && "should not be reached in fuzz")` to keep the harness
  deterministic.

No `compile_commands.json` is required – the codebase is only three C files and
can be built directly in the harness.

