// ============================================================================
// fw/config.hpp — ServerConfig — listener/bootstrap configuration.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/limits.hpp"

namespace fw {

// ---- thread-pool sizing policy ----------------------------------------------
// Rationale (documented in README §Threading):
//   * io threads run the event loop; all socket work is non-blocking and
//     coroutine-based, so more threads than cores only adds cache/mutex
//     traffic. Auto = hardware threads, clamped to [2, 16]: the floor keeps
//     accept/timers off the single hot thread, the ceiling guards against
//     containers that report the host's 128 cores to a 2-vCPU cgroup.
//     hardware_concurrency()==0 (unknown) falls back to 4.
//   * the blocking pool exists so file I/O and other inherently blocking
//     handler work never stalls an io thread. It needs far less parallelism
//     (disk-bound, not CPU-bound): auto = clamp(cores/4, 2, 8).
// Both are overrides-first: --threads / --blocking-threads beat the policy.
inline unsigned auto_io_threads() {
  const unsigned hw = std::thread::hardware_concurrency();
  if (hw == 0) return 4;
  return std::clamp(hw, 2u, 16u);
}

inline unsigned auto_blocking_threads() {
  const unsigned hw = std::thread::hardware_concurrency();
  return std::clamp(hw / 4, 2u, 8u);
}

struct ServerConfig {
  std::string bind_addr = "0.0.0.0";
  unsigned port = 8080;
  std::filesystem::path docroot = "public";
  std::string tls_cert, tls_key;
  bool allow_h2c = true;     // cleartext HTTP/2 prior-knowledge
  bool http1_only = false;   // disable HTTP/2 entirely
  bool strict_tls = false;   // refuse plaintext on the TLS port
  std::size_t max_upload_bytes = 50ull * 1024 * 1024;  // /chat/upload cap
  int threads = 0;           // 0 → auto (auto_io_threads)
  int blocking_threads = 0;  // 0 → auto (auto_blocking_threads)
  bool verbose = false;
  bool selftest = false;
  std::size_t max_body_bytes = 1 * 1024 * 1024;
  Limits limits;             // io/keepalive/handshake timeouts & caps
};
}  // namespace fw
