ftp_cmd_parser_fuzz

Scope and goal
- Fuzz the FTP control-connection command parser to explore command dispatch, argument parsing, and state transitions without depending on a real network peer. Favor high-level, attacker-controlled inputs (FTP command lines) that are reachable over the wire.

Top entrypoints (ranked)
1) ftpd::parser
   - Why reachable: Parses all commands received on the FTP control socket; every client message hits this first.
   - Evidence: ftpd.c:263 (definition), ftpd.c:338 and ftpd.c:344 (PORT/EPRT parsing), ftpd.c:385 (RETR dispatch), ftpd.c:400–476 (numerous command handlers dispatched).
   - Init: Set benign state to avoid privileged paths: `loggedin=1`, `guest=0`, `type=2`, `idletime=1`, `strcpy(wd, "/")`, zero `datafd`, clear `renamefrom`. Initialize `peer`/`ctrlconn` to 127.0.0.1.
   - Preconditions/tricky bits:
     - parser() reads from STDIN via sfgets(). Feed fuzzer bytes to a pipe dup’d onto fd 0, and terminate with at least one newline. Interpose `exit()` (wrap) to avoid killing the process on EOF/timeouts (sfgets and some fatal paths call exit()).
     - Some commands auto-login via `douser(NULL)` if not already logged in; pre-set `loggedin=1` to bypass chroot/set*id paths.
     - Data-connection commands (LIST/RETR/STOR) will call `opendata()`. With `datafd=0` they fail gracefully (no accept/connect), allowing the parser to proceed without real sockets.

2) ftpd::docwd
   - Why reachable: `CWD`/`CDUP` path parsing is directly controlled by clients and widely exercised.
   - Evidence: ftpd.c:674 (definition), ftpd.c:374 and ftpd.c:378 (dispatch from parser).
   - Init: `loggedin=1`; set `wd` to "/"; ensure process CWD points to a temp/sandbox directory.
   - Preconditions/tricky bits: Handles `~user/...` expansion for non-guest users; guard against unintended chdir by sandboxing the harness working directory.

3) ls::donlist
   - Why reachable: `LIST`/`NLST` option and pattern parsing is user-controlled; historically a rich source of bugs (globs, recursion, formatting).
   - Evidence: ls.c:540 (definition), ls.c:546–586 (flag parsing), ls.c:596 (calls `opendata()`), ls.c:673–739 (globbing and recursive listing).
   - Init: `type=1` or `2`, `loggedin=1`, `wd="/"`, ensure a small test directory tree exists.
   - Preconditions/tricky bits: `donlist()` calls `opendata()` early and returns if it fails. To reach globs/listing logic, wrap `opendata()` to return a writable fd (e.g., a pipe) and no-op network. Alternatively exercise `donlist()` via `parser()` (target #1) and allow it to fail fast on data-conn commands for parser coverage.

4) ftpd::douser
   - Why reachable: `USER` is issued by every client; input fully attacker-controlled.
   - Evidence: ftpd.c:513 (definition), ftpd.c:372 (dispatch). Reads passwd/shadow and sets account state.
   - Init: Provide a benign environment (non-root). Avoid CHROOT paths by not triggering anonymous user (pass NULL only from parser; for direct harness, pass a non-"ftp" username).
   - Preconditions/tricky bits: Touches `setregid`, `initgroups`, and `setreuid`; run unprivileged and allow failures, or wrap them to return success in the harness to explore more code.

5) ftpd::dopass
   - Why reachable: `PASS` follows `USER` and uses the supplied password.
   - Evidence: ftpd.c:619 (definition), ftpd.c:374 (dispatch). Uses `crypt()` and group listing output.
   - Init: Set `cpwd` (e.g., from a previous `douser()` call or stub) and `account`. Avoid chroot by leaving `userchroot=0`.
   - Preconditions/tricky bits: Interacts with system NSS and `crypt()`. Consider wrapping `crypt()` or constraining inputs to keep runs fast.

6) ftpd::doretr
   - Why reachable: Client-controlled file path for downloads; used by many clients.
   - Evidence: ftpd.c:952 (definition), ftpd.c:385 (dispatch).
   - Init: Provide a small corpus directory with various files. `datafd=0` causes `opendata()` to fail and return; earlier checks (stat/mmap branch selection) still execute.
   - Preconditions/tricky bits: Uses `mmap` and large writes; wrap `opendata()` to a pipe or leave `datafd=0` for shallow coverage.

7) ftpd::dostor
   - Why reachable: Client-controlled file path and content for uploads.
   - Evidence: ftpd.c:1177 (definition), ftpd.c:392 (dispatch).
   - Init: Ensure sandbox write directory; `guest=0` to avoid overwrite restrictions; set `type` to 1/2.
   - Preconditions/tricky bits: Reads from data socket; without a wrapped `opendata()` it returns early. If wrapped, feed limited data to avoid excessive I/O.

8) ftpd::domdtm and ftpd::dosize
   - Why reachable: Metadata queries commonly used by clients.
   - Evidence: ftpd.c:1328 (MDTM), ftpd.c:1355 (SIZE); parser dispatch at ftpd.c:465–468.
   - Init: Provide files; set `wd` and CWD; no network needed.
   - Preconditions/tricky bits: Simple file lstat/formatting; fast signal-path target.

Best initial harness: ftp_cmd_parser_fuzz
- Reason: Highest-level, exercises command lexing and dispatch for many FTP verbs (USER, PASS, CWD, TYPE, MODE, STRU, RNFR/RNTO, MDTM, SIZE, DELE, SITE, etc.). Network-heavy verbs safely short-circuit with `datafd=0`. Good branch structure in one place; minimal one-time init.

Harness sketch (libFuzzer)
- Prototype: `int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)`
- Map input to multiple FTP lines: split on `\n`, ensure at least one `\n`.
- Redirect STDIN: create a pipe; write the fuzz buffer; dup read end to fd 0 so `sfgets()` consumes it.
- Global init (once):
  - Set `loggedin=1`, `guest=0`, `type=2`, `idletime=1`; `strcpy(wd, "/")`; zero `datafd`; `renamefrom=NULL`.
  - Initialize `peer` and `ctrlconn` to 127.0.0.1 with ephemeral ports.
- Interpositions (linker wraps) to keep runs in-process:
  - `-Wl,--wrap=exit` to prevent process termination; treat as early-return from the call site.
  - Optionally wrap: `opendata`, `connect`, `accept`, `socket`, `bind`, `listen`, `chroot`, `setreuid`, `setregid`, `initgroups` to no-op/succeed in the harness.
- Note on timeouts: `sfgets()` uses `select()` with `idletime`; ensure harness writes enough data or keep `idletime` small and wrap `exit`.

Build notes
- Repo uses a Makefile; the binary target is `ftpd`. For libFuzzer/ASan/UBSan builds, recompile objects with clang and link the harness with `-fsanitize=fuzzer,address,undefined`.
- If needed by your build system or IDE for code navigation, generate `compile_commands.json` (e.g., with Bear or CMake export). Do not generate it in this step.

Seed ideas
- Control-channel lines: combinations of known verbs and malformed arguments: `USER`, `PASS`, `CWD`, `CDUP`, `TYPE`, `MODE`, `STRU`, `PORT/EPRT` variants, `PASV/EPSV`, `REST`, `RNFR/RNTO`, `SIZE`, `MDTM`, `SITE idle`, `LIST` forms (flags + globs).
- Path edge cases: empty, `.`/`..`, long components, leading `~user/`, embedded NUL (filtered by parser), non-UTF-8 bytes.

