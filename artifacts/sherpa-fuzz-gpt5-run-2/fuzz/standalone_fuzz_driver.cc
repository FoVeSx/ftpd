// Minimal standalone driver to run an LLVMFuzzerTestOneInput()-style target
// without requiring libFuzzer. Used when building with g++.

#include <cstddef>
#include <cstdint>
#include <vector>
#include <fstream>
#include <iterator>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static void run_one(const std::vector<uint8_t>& buf) {
  if (!buf.empty()) {
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  } else {
    // Exercise empty input too
    LLVMFuzzerTestOneInput(nullptr, 0);
  }
}

int main(int argc, char** argv) {
  std::ios::sync_with_stdio(false);
  if (argc > 1) {
    for (int i = 1; i < argc; ++i) {
      std::ifstream ifs(argv[i], std::ios::binary);
      if (!ifs) continue;
      std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());
      run_one(data);
    }
  } else {
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(std::cin)),
                              std::istreambuf_iterator<char>());
    run_one(data);
  }
  return 0;
}

