// ============================================================================
// fw/listener.hpp — Listener — one port, three protocols: sniffs the first bytes of every connection (TLS ClientHello / h2c preface / h1), negotiates ALPN, spawns the right session.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"
#include "fw/config.hpp"
#include "fw/app.hpp"
#include "fw/shutdown.hpp"
#include "fw/prefaced_stream.hpp"
#include "fw/http1_session.hpp"
#include "fw/http2_session.hpp"

namespace fw {
// ---------------------------------------------------------------------------
class Listener {
 public:
  Listener(asio::io_context& ioc, App& app, const ServerConfig& cfg,
           ShutdownRegistry& reg)
      : ioc_(ioc), app_(app), cfg_(cfg), reg_(reg), acceptor_(ioc) {
    h2_enabled_ =
#if FW_HTTP2
        !cfg.http1_only;
#else
        false;
#endif
  }

  bool start(std::string& err) {
    asio::error_code ec;
    const asio::ip::address addr = asio::ip::make_address(cfg_.bind_addr, ec);
    if (ec) { err = "invalid bind address: " + cfg_.bind_addr; return false; }
    const asio::ip::tcp::endpoint ep(addr, static_cast<unsigned short>(cfg_.port));
    acceptor_.open(ep.protocol(), ec);
    if (ec) { err = "open: " + ec.message(); return false; }
    acceptor_.set_option(asio::socket_base::reuse_address(true), ec);
    acceptor_.bind(ep, ec);
    if (ec) { err = "bind: " + ec.message(); return false; }
    acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) { err = "listen: " + ec.message(); return false; }

#if FW_TLS
    if (!cfg_.tls_cert.empty() && !cfg_.tls_key.empty()) {
      if (!setup_tls_(err)) return false;
    }
#endif

    asio::co_spawn(ioc_.get_executor(),
                   [this] -> asio::awaitable<void> { co_await accept_loop_(); },
                   asio::detached);
    return true;
  }

  void stop() {
    asio::post(ioc_.get_executor(), [this] {
      asio::error_code ig;
      acceptor_.close(ig);
    });
  }

 private:
#if FW_TLS
  static int alpn_select_cb_(SSL*, const unsigned char** out,
                             unsigned char* outlen, const unsigned char* in,
                             unsigned int inlen, void* arg) {
    const bool has_h2 = *static_cast<bool*>(arg);
    static const unsigned char kH1[] = "http/1.1";
    bool client_h1 = false;
    unsigned i = 0;
    while (i < inlen) {
      const unsigned l = in[i++];
      if (i + l > inlen) return SSL_TLSEXT_ERR_NOACK;
      if (has_h2 && l == 2 && in[i] == 'h' && in[i + 1] == '2') {
        *out = in + i;
        *outlen = 2;
        return SSL_TLSEXT_ERR_OK;
      }
      if (l == 8 && std::memcmp(in + i, "http/1.1", 8) == 0) client_h1 = true;
      i += l;
    }
    if (client_h1) {
      *out = kH1;
      *outlen = 8;
      return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;  // no overlap → continue as HTTP/1.1
  }

  bool setup_tls_(std::string& err) {
    try {
      ssl_ctx_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_server);
      SSL_CTX* native = ssl_ctx_->native_handle();
      ::SSL_CTX_set_min_proto_version(native, TLS1_2_VERSION);
      ::SSL_CTX_set_options(native, SSL_OP_NO_RENEGOTIATION);
      ::SSL_CTX_set_session_id_context(
          native, reinterpret_cast<const unsigned char*>("fw-h2"), 4);
      ::SSL_CTX_set_alpn_select_cb(native, &Listener::alpn_select_cb_, &h2_enabled_);
      ssl_ctx_->use_certificate_chain_file(cfg_.tls_cert);
      ssl_ctx_->use_private_key_file(cfg_.tls_key, asio::ssl::context::pem);
      return true;
    } catch (const std::exception& e) {
      err = std::string("tls setup: ") + e.what();
      ssl_ctx_.reset();
      return false;
    }
  }
#endif

  asio::awaitable<void> accept_loop_() {
    for (;;) {
      asio::ip::tcp::socket peer{asio::make_strand(ioc_)};
      auto [ec] = co_await acceptor_.async_accept(
          peer, asio::as_tuple(asio::use_awaitable));
      if (ec) {
        if (ec == asio::error::operation_aborted ||
            ec == asio::error::bad_descriptor)
          co_return;  // listener stopped
        if (ec == std::errc::too_many_files_open ||
            ec == std::errc::too_many_files_open_in_system ||
            ec == std::errc::no_buffer_space) {
          log(LogLevel::Warn, "accept: {} — pausing 100 ms", ec.message());
          asio::steady_timer t(co_await asio::this_coro::executor,
                               std::chrono::milliseconds(100));
          co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
          continue;
        }
        log(LogLevel::Warn, "accept: {}", ec.message());
        continue;
      }
      auto ex = peer.get_executor();
      asio::co_spawn(ex,
                     [this, p = std::move(peer)]() mutable
                     -> asio::awaitable<void> {
                       co_await run_peer_(std::move(p));
                     },
                     asio::detached);
    }
  }

  // ---- protocol sniffing ------------------------------------------------------
  enum class Proto { Dead, TlsRecord, H2Preface, Http1 };
  struct Sniff {
    Proto proto = Proto::Dead;
    std::string bytes;  // everything read while sniffing (prefed to the session)
  };

  // Read the first bytes of a connection and classify it:
  //   * TLS ClientHello (first byte 0x16)                      → TlsRecord
  //   * HTTP/2 preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"      → H2Preface
  //   * anything that diverges from both (usual "GET ...")     → Http1
  // NB: the preface itself contains "\r\n\r\n" — that sequence must NOT be
  // treated as "a complete HTTP/1 header block" (that was a real bug); the
  // byte-wise prefix comparison alone classifies every case correctly and
  // survives arbitrary packet fragmentation.
  asio::awaitable<Sniff> sniff_(asio::ip::tcp::socket& s) {
    static constexpr std::string_view kPreface =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    Sniff r;
    std::string& acc = r.bytes;
    acc.reserve(128);  // preface is 24 B; one read usually settles it
    for (;;) {
      if (!acc.empty()) {
        if (static_cast<unsigned char>(acc[0]) == 0x16) {
          r.proto = Proto::TlsRecord;
          co_return r;
        }
        const std::size_t cmp = std::min(acc.size(), kPreface.size());
        if (acc.compare(0, cmp, kPreface, 0, cmp) != 0) {
          r.proto = Proto::Http1;
          co_return r;
        }
        if (acc.size() >= kPreface.size()) {
          r.proto = Proto::H2Preface;
          co_return r;
        }
      }
      std::array<char, 4096> b{};
      auto [ec, n] = co_await s.async_read_some(
          asio::buffer(b),
          fw::cancel_after(cfg_.limits.handshake_timeout,
                           asio::as_tuple(asio::use_awaitable)));
      if (ec || n == 0) co_return r;  // dead peer / timeout → Proto::Dead
      acc.append(b.data(), n);
    }
  }

  asio::awaitable<void> run_peer_(asio::ip::tcp::socket peer) {
    const Sniff sn = co_await sniff_(peer);
    if (sn.proto == Proto::Dead) co_return;

#if FW_TLS
    if (sn.proto == Proto::TlsRecord && ssl_ctx_) {
      // Hand the sniffed bytes back through PrefacedStream, then TLS.
      using TlsStream = asio::ssl::stream<
          PrefacedStream<asio::ip::tcp::socket>>;
      TlsStream tls(
          PrefacedStream<asio::ip::tcp::socket>(std::move(peer),
                                                std::move(sn.bytes)),
          *ssl_ctx_);
      auto [ec] = co_await tls.async_handshake(
          asio::ssl::stream_base::server,
          fw::cancel_after(cfg_.limits.handshake_timeout,
                           asio::as_tuple(asio::use_awaitable)));
      if (ec) {
        log(LogLevel::Debug, "tls handshake failed: {}", ec.message());
        co_return;
      }
      const unsigned char* a = nullptr;
      unsigned int alen = 0;
      ::SSL_get0_alpn_selected(tls.native_handle(), &a, &alen);
      const std::string alpn(reinterpret_cast<const char*>(a), alen);
      const bool want_h2 = h2_enabled_ && alpn == "h2";
      log(LogLevel::Debug, "tls conn: alpn='{}' → {}", alpn.empty() ? "(none)" : alpn,
          want_h2 ? "h2" : "h1");
#if FW_HTTP2
      if (want_h2) {
        auto sess = std::make_shared<h2::Http2Session<TlsStream>>(
            std::move(tls), app_, reg_, "", true, alpn);
        co_await sess->run();
        co_return;
      }
#endif
      auto sess = std::make_shared<h1::Http1Session<TlsStream>>(
          std::move(tls), app_, reg_, "", true, alpn);
      co_await sess->run();
      co_return;
    }
#endif  // FW_TLS

    if (sn.proto == Proto::TlsRecord) {
      // A TLS ClientHello arrived but no certificate is configured.
      log(LogLevel::Warn,
          "peer sent a TLS ClientHello but TLS is disabled "
          "(start with --tls-cert/--tls-key) — closing");
      co_return;
    }

#if FW_HTTP2
    if (sn.proto == Proto::H2Preface && cfg_.allow_h2c && !cfg_.http1_only) {
      log(LogLevel::Debug, "plaintext conn: h2c prior-knowledge");
      auto sess = std::make_shared<h2::Http2Session<asio::ip::tcp::socket>>(
          std::move(peer), app_, reg_, std::move(sn.bytes), false, "");
      co_await sess->run();
      co_return;
    }
#endif

    // Plain HTTP/1.x (optionally on the TLS port — served anyway unless
    // --strict-tls; that is what makes `curl http://host:8443/...` and old
    // plain clients work instead of dying in a TLS handshake).
#if FW_TLS
    if (ssl_ctx_) {
      if (cfg_.strict_tls) {
        log(LogLevel::Warn, "plaintext on TLS port — refused (--strict-tls)");
        co_return;
      }
      log(LogLevel::Warn,
          "plaintext HTTP/1.1 on TLS port — serving anyway "
          "(use --strict-tls to refuse)");
    }
#endif
    auto sess = std::make_shared<h1::Http1Session<asio::ip::tcp::socket>>(
        std::move(peer), app_, reg_, std::move(sn.bytes), false, "");
    co_await sess->run();
  }

  asio::io_context& ioc_;
  App& app_;
  const ServerConfig& cfg_;
  ShutdownRegistry& reg_;
  asio::ip::tcp::acceptor acceptor_;
  bool h2_enabled_ = false;
#if FW_TLS
  std::unique_ptr<asio::ssl::context> ssl_ctx_;
#endif
};

}  // namespace fw
