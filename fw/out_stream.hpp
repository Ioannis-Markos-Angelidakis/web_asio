// ============================================================================
// fw/out_stream.hpp — OutStream — push side of a streamed response: bounded concurrent_channel, one drain coroutine per stream, natural backpressure, no concurrent writers.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// OutStream — push-side of a streamed (chunked / SSE) response.
//
//  * Built on asio::experimental::concurrent_channel: producers may call
//    send()/send_await()/finish()/close() from any thread (hub broadcast,
//    file pool), the single drain coroutine consumes on the connection
//    strand → no concurrent writers, natural backpressure.
//  * send()        — non-blocking; a full channel aborts the stream
//                    (bounded memory beats unbounded buffering).
//  * send_await()  — backpressured enqueue for streaming producers.
//  * finish()      — graceful end (sentinel is delivered after all queued
//                    data because async_send enqueues FIFO).
//  * close()       — abortive end (queued frames are dropped).
// ---------------------------------------------------------------------------
class OutStream : public std::enable_shared_from_this<OutStream> {
 public:
  OutStream(asio::any_io_executor strand_ex, std::size_t capacity)
      : ex_(std::move(strand_ex)),
        ch_(ex_, capacity),
        close_wait_(ex_) {
    close_wait_.expires_at(
        (std::chrono::steady_clock::time_point::max)());
  }

  // ---- producer side (any thread) --------------------------------------------
  void send(std::string chunk) {
    if (closed_.load(std::memory_order_relaxed) || chunk.empty()) return;
    if (!ch_.try_send(asio::error_code{}, std::move(chunk)))
      close();  // slow consumer → abort (bounded memory)
  }

  asio::awaitable<void> send_await(std::string chunk) {
    if (closed_.load(std::memory_order_relaxed) || chunk.empty()) co_return;
    auto [ec] = co_await ch_.async_send(asio::error_code{}, std::move(chunk),
                                        asio::as_tuple(asio::use_awaitable));
    if (ec) close();
  }

  void finish() {
    if (finishing_.exchange(true)) return;
    // Deliver the sentinel even if the channel is momentarily full: the
    // async_send waits for capacity (FIFO behind already-queued data).
    asio::co_spawn(
        ex_,
        [self = shared_from_this()]() -> asio::awaitable<void> {
          if (self->closed_.load(std::memory_order_relaxed)) co_return;
          auto [ec] = co_await self->ch_.async_send(
              asio::error_code{}, std::string{},
              asio::as_tuple(asio::use_awaitable));
          (void)ec;
        },
        asio::detached);
  }

  void close() {
    if (closed_.exchange(true)) return;
    ch_.close();
    asio::post(ex_, [self = shared_from_this()] {
      self->close_wait_.cancel();
    });
  }

  bool closed() const { return closed_.load(std::memory_order_relaxed); }
  bool finished() const { return finishing_.load(std::memory_order_relaxed); }

  // ---- drain side (connection strand, single consumer) -----------------------
  asio::awaitable<std::optional<std::string>> receive() {
    auto [ec, s] = co_await ch_.async_receive(asio::as_tuple(asio::use_awaitable));
    if (ec) co_return std::nullopt;
    co_return std::optional<std::string>(std::move(s));
  }

  // Handler side: suspends until close()/abort/cancellation, then throws
  // system_error(operation_aborted) — callers use scope guards to detach.
  asio::awaitable<void> wait_closed() {
    co_await close_wait_.async_wait(asio::use_awaitable);
  }

  // Called by the drain coroutine after it has ended the wire stream.
  void mark_drained_and_close() {
    if (closed_.exchange(true)) return;
    ch_.close();
    close_wait_.cancel();
  }

 private:
  asio::any_io_executor ex_;
  asio::experimental::concurrent_channel<void(asio::error_code, std::string)> ch_;
  asio::steady_timer close_wait_;
  std::atomic<bool> closed_{false};
  std::atomic<bool> finishing_{false};
};

}  // namespace fw
