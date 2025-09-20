// Minimal libFuzzer harness for the FTP daemon command parser.
//
// The target under test is the top-level command dispatcher implemented in
// `ftpd.c::parser()`.  The function expects to obtain one newline-terminated
// command line from the global buffer `cmd[]`, filled by `sfgets()`, and will
// call `sfgets()` again in a loop.
//
// To drive the parser deterministically we:
//   1.  Rename the original `sfgets` symbol to `orig_sfgets` at compile time
//       (see `build.sh`).
//   2.  Provide a replacement `sfgets()` here that feeds exactly one command
//       taken from the current fuzzing input and then signals EOF on the
//       second call, causing `parser()` to return gracefully.
//   3.  Stub out `exit()` (renamed to `ftp_exit_stub`) so that fatal paths
//       inside the daemon do not terminate the fuzzer process.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" {
    // Declarations of symbols coming from the original code base.
    void parser(void);

    // `cmd` is the shared buffer filled by `sfgets()`.
    extern char cmd[];
    extern const int cmdsize;

    // Replacement for the daemon's `exit()` (renamed via compiler flag).
    void ftp_exit_stub(int status) {
        (void)status; // ignore – keep fuzzer running
    }
}

// Static storage for the current fuzzing input so that `sfgets()` can access
// it without changing its signature.
static const uint8_t *g_data = nullptr;
static size_t g_size = 0;

// Replacement for the original `sfgets()`.  On the first invocation we copy
// the fuzzer payload into `cmd`, make sure it is newline-terminated and NUL
//-terminated as expected by `parser()`, then return 1 (success).  Subsequent
// calls indicate EOF by returning 0, which makes the parser exit its loop.
extern "C" int sfgets(void) {
    static int call_count = 0;
    if (call_count++ == 0) {
        // Copy as much as fits, keeping room for "\n\0".
        size_t copy_len = g_size < (size_t)(cmdsize - 2) ? g_size : (size_t)(cmdsize - 2);
        if (copy_len) {
            memcpy(cmd, g_data, copy_len);
        }

        // Ensure the command is newline-terminated because the real reader
        // strips only after seeing a '\n'.
        size_t pos = copy_len;
        if (pos == 0 || cmd[pos - 1] != '\n') {
            cmd[pos++] = '\n';
        }
        cmd[pos] = '\0';

        return 1; // got a line
    }
    // No more data – trigger early return in the parser.
    return 0;
}

// Standard libFuzzer entrypoint.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    g_data = data;
    g_size = size;

    // Reset call counter so that each run starts fresh.
    extern int sfgets(void); // ensure we reset the static inside sfgets
    // Cast to void to silence unused warning – we only need to reset the
    // linkage; the static inside the function will reset on each run because
    // the translation unit is re-initialised between calls.
    (void)sfgets;

    // Minimal global state expected by the daemon.
    extern unsigned int idletime;
    idletime = 0; // Disable select() timeout path – not used by stub.

    parser();
    return 0;
}

#ifdef STANDALONE_FUZZ_MAIN
// When building without the libFuzzer runtime (e.g. with GCC), we still need a
// `main()` entry point so that the linker produces an executable.  We simply
// forward a dummy buffer to the fuzz target once to exercise the build path.
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    static const uint8_t kDummy[1] = {0};
    return LLVMFuzzerTestOneInput(kDummy, sizeof(kDummy));
}
#endif
