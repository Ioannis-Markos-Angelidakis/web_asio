// ============================================================================
// fw/limits.hpp — Every size cap and clock the server enforces, checked before any allocation on untrusted input.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// Limits (all enforced before any allocation based on untrusted input)
// ---------------------------------------------------------------------------
struct Limits {
  std::size_t max_header_bytes      = 32 * 1024;   // → 431
  std::size_t max_headers           = 100;         // → 431
  std::size_t max_body_bytes        = 1 * 1024 * 1024;  // → 413 (h1) / RST (h2)
  // Streaming buffers: the OutStream channel is bounded per MESSAGE (32 ×
  // 16 KiB file chunks ≈ 512 KiB in flight per stream, and ≥32 SSE frames),
  // the h2 sendq cap is a generous safety net on top (flow control + the
  // channel already provide the real backpressure).
  std::size_t max_sse_outbox        = 32;          // frames/chunks per stream
  std::chrono::milliseconds io_timeout      = std::chrono::duration_cast<std::chrono::milliseconds>(kIoTimeout);
  std::chrono::milliseconds idle_keepalive  = std::chrono::duration_cast<std::chrono::milliseconds>(kIdleKeepAlive);
  std::chrono::milliseconds h2_idle_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(kH2IdleTimeout);
  std::chrono::milliseconds handshake_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(kHandshakeTimeout);
  std::chrono::milliseconds request_deadline = std::chrono::duration_cast<std::chrono::milliseconds>(kRequestDeadline);  // whole-request cap (slowloris)
  std::size_t max_h2_streams        = 100;         // SETTINGS_MAX_CONCURRENT_STREAMS
  std::size_t max_h2_stream_buffer  = 1 * 1024 * 1024;  // h2 sendq safety net
  std::size_t h2_sendq_high_water   = 256 * 1024;  // drain pauses above this;
                                                  // provider signals below high/4
  std::size_t small_file_bytes      = 64 * 1024;   // below: whole-file response
};
}  // namespace fw
