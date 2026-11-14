// ============================================================================
// fw/config.hpp — ServerConfig — listener/bootstrap configuration.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/limits.hpp"

namespace fw {
struct ServerConfig {
  std::string bind_addr = "0.0.0.0";
  unsigned port = 8080;
  std::filesystem::path docroot = "public";
  std::string tls_cert, tls_key;
  bool allow_h2c = true;     // cleartext HTTP/2 prior-knowledge
  bool http1_only = false;   // disable HTTP/2 entirely
  bool strict_tls = false;   // refuse plaintext on the TLS port
  std::size_t max_upload_bytes = 50ull * 1024 * 1024;  // /chat/upload cap
  int threads = 0;           // 0 → auto
  bool verbose = false;
  bool selftest = false;
  std::size_t max_body_bytes = 1 * 1024 * 1024;
  Limits limits;             // io/keepalive/handshake timeouts & caps
};
}  // namespace fw
