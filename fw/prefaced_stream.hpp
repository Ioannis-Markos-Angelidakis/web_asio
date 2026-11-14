// ============================================================================
// fw/prefaced_stream.hpp — PrefacedStream — next-layer adapter that replays the bytes consumed by protocol sniffing into the TLS handshake.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"

#if FW_TLS

namespace fw {
// ---------------------------------------------------------------------------
// PrefacedStream — next-layer adapter for asio::ssl::stream.
//
// Protocol sniffing must READ the first bytes of a connection before we know
// whether the peer speaks TLS at all. Those bytes are handed back here: the
// ssl::stream's handshake first consumes them, then reads from the socket.
// (asio::ssl::stream has no public "unget" API, so we wrap the next layer.)
//
// Completion handlers are always invoked as-if posted to their associated
// executor — never inline from the initiating call — matching asio semantics.
// ---------------------------------------------------------------------------
template <class Inner>
class PrefacedStream {
 public:
  using executor_type = typename Inner::executor_type;
  using lowest_layer_type = typename Inner::lowest_layer_type;

  PrefacedStream(Inner inner, std::string pending)
      : inner_(std::move(inner)), pending_(std::move(pending)) {}

  PrefacedStream(PrefacedStream&& other) noexcept
      : inner_(std::move(other.inner_)),
        pending_(std::move(other.pending_)),
        pos_(other.pos_) {}

  executor_type get_executor() noexcept { return inner_.get_executor(); }
  lowest_layer_type& lowest_layer() { return inner_.lowest_layer(); }
  const lowest_layer_type& lowest_layer() const {
    return inner_.lowest_layer();
  }

  template <typename BufferSeq, typename Token>
  auto async_read_some(const BufferSeq& buffers, Token&& token) {
    return asio::async_initiate<Token, void(asio::error_code, std::size_t)>(
        [this](auto handler, const BufferSeq& bufs) {
          const std::size_t avail =
              pos_ < pending_.size() ? pending_.size() - pos_ : 0;
          const std::size_t want = asio::buffer_size(bufs);
          if (want == 0) {
            // Zero-sized read (asio's ssl engine uses this to defer the
            // handler): complete with 0 bytes, as-if posted.
            auto ex = asio::get_associated_executor(handler,
                                                    inner_.get_executor());
            asio::post(ex, [h = std::move(handler)]() mutable {
              h(asio::error_code{}, std::size_t{0});
            });
            return;
          }
          if (avail == 0) {  // pre-read bytes exhausted → straight to socket
            inner_.async_read_some(bufs, std::move(handler));
            return;
          }
          const std::size_t n = std::min(avail, want);
          std::size_t copied = 0;
          for (auto it = asio::buffer_sequence_begin(bufs);
               it != asio::buffer_sequence_end(bufs) && copied < n; ++it) {
            copied += asio::buffer_copy(
                *it, asio::buffer(pending_.data() + pos_ + copied,
                                  n - copied));
          }
          pos_ += copied;
          auto ex = asio::get_associated_executor(handler,
                                                  inner_.get_executor());
          asio::post(ex, [h = std::move(handler), copied]() mutable {
            h(asio::error_code{}, copied);
          });
        },
        token, buffers);
  }

  template <typename BufferSeq, typename Token>
  auto async_write_some(const BufferSeq& buffers, Token&& token) {
    return inner_.async_write_some(buffers, std::forward<Token>(token));
  }

 private:
  Inner inner_;
  std::string pending_;
  std::size_t pos_ = 0;
};
}  // namespace fw
#endif  // FW_TLS
