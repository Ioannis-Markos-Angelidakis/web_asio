// ============================================================================
// fw/latch.hpp — Latch — one-shot async event (thread-safe hit()).
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// Latch — one-shot async event (thread-safe hit())
// ---------------------------------------------------------------------------
class Latch {
 public:
  explicit Latch(asio::any_io_executor ex)
      : ch_(std::move(ex), 1) {}
  void hit() { ch_.try_send(asio::error_code{}); }
  asio::awaitable<void> wait() {
    auto [ec] = co_await ch_.async_receive(asio::as_tuple(asio::use_awaitable));
    (void)ec;
  }

 private:
  asio::experimental::concurrent_channel<void(asio::error_code)> ch_;
};

}  // namespace fw
