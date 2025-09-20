// Minimal libFuzzer harness for ftpd::parser
// Feeds FTP command lines via STDIN pipe and keeps process in-process by
// interposing exit() to a longjmp back to the fuzzer.

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <setjmp.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" {
#include "ftpd.h"

// ftpd.c globals not declared in ftpd.h
extern unsigned int idletime;
extern int datafd;
extern struct sockaddr_in ctrlconn;
extern struct sockaddr_in peer;
extern unsigned short int peerdataport;
extern int passive;
extern int candownload;

// entrypoint we want to exercise
void parser(void);
}

// Interpose exit() so fatal paths inside the target do not terminate the process.
static jmp_buf fuzz_exit_env;
static int fuzz_exit_env_ready = 0;

extern "C" void __wrap_exit(int status) {
  (void)status;
  if (fuzz_exit_env_ready) {
    longjmp(fuzz_exit_env, 1);
  }
  // As a fallback, just return (best-effort to keep process alive).
}

static void global_init_once() {
  static int initialized = 0;
  if (initialized) return;
  initialized = 1;

  // Minimal benign state
  loggedin = 1;
  guest = 0;
  type = 2; // binary
  idletime = 1; // short timeout windows for select()
  candownload = 1;
  datafd = 0;
  passive = 0;
  peerdataport = 0;
  strcpy(wd, "/");

  // Loopback addresses for control/data endpoints
  memset(&ctrlconn, 0, sizeof(ctrlconn));
  ctrlconn.sin_family = AF_INET;
  inet_aton("127.0.0.1", &ctrlconn.sin_addr);
  ctrlconn.sin_port = htons(0); // ephemeral

  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  inet_aton("127.0.0.1", &peer.sin_addr);
  peer.sin_port = htons(0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  global_init_once();

  // Ensure at least one newline so sfgets() can complete a read cycle.
  if (size == 0) return 0;

  // Prepare an input buffer that ends with a newline
  bool has_nl = false;
  for (size_t i = 0; i < size; i++) {
    if (data[i] == '\n') { has_nl = true; break; }
  }

  size_t buf_len = size + (has_nl ? 0 : 1);
  if (buf_len > (1u<<20)) return 0; // keep it sane
  char *buf = (char*)malloc(buf_len);
  if (!buf) return 0;
  memcpy(buf, data, size);
  if (!has_nl) buf[buf_len - 1] = '\n';

  // Create a pipe and hook it up to STDIN so sfgets() reads fuzzer bytes.
  int pfd[2];
  if (pipe(pfd) != 0) {
    free(buf);
    return 0;
  }

  // Best effort to avoid interfering with the terminal if any.
  int old_stdin = dup(0);
  (void)old_stdin;

  // Write all data then close write end to allow EOF handling if reached.
  ssize_t off = 0;
  while ((size_t)off < buf_len) {
    ssize_t w = write(pfd[1], buf + off, buf_len - off);
    if (w <= 0) break;
    off += w;
  }
  close(pfd[1]);

  // Redirect read end to STDIN (fd 0)
  (void)dup2(pfd[0], 0);
  close(pfd[0]);

  // Call into the target; if it calls exit(), jump back here.
  fuzz_exit_env_ready = 1;
  if (setjmp(fuzz_exit_env) == 0) {
    parser();
  }
  fuzz_exit_env_ready = 0;

  free(buf);
  return 0;
}
