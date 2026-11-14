// ============================================================================
// fw/http1_session.hpp — HTTP/1.1 session — hardened parser (smuggling guards, size caps), keep-alive loop, chunked bodies, Expect:100-continue, single-writer streaming.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"
#include "fw/message.hpp"
#include "fw/limits.hpp"
#include "fw/latch.hpp"
#include "fw/out_stream.hpp"
#include "fw/hooks.hpp"
#include "fw/app.hpp"
#include "fw/shutdown.hpp"

namespace fw {
namespace h1 {

// Control-flow exceptions for the HTTP/1.1 session.
struct RequestError { int status; std::string msg; };  // → error page, close
struct ConnClosed   { asio::error_code ec; };          // silent close

template <class Stream>
class Http1Session final : public ServerHooks,
                           public ShutdownTarget,
                           public std::enable_shared_from_this<Http1Session<Stream>> {
 public:
  Http1Session(Stream sock, App& app, ShutdownRegistry& reg, std::string pre_read,
               bool tls, std::string alpn)
      : sock_(std::move(sock)),
        app_(app),
        reg_(reg),
        rbuf_(std::move(pre_read)),
        tls_(tls),
        alpn_(std::move(alpn)) {
    rbuf_.reserve(64 * 1024);
  }

  asio::awaitable<void> run() {
    auto self = this->shared_from_this();
    reg_.add(self);
    RegGuard rg{reg_, self};
    asio::error_code ig;
    if constexpr (std::is_same_v<Stream, asio::ip::tcp::socket>) {
      sock_.set_option(asio::ip::tcp::no_delay(true), ig);
    } else {
      sock_.lowest_layer().set_option(asio::ip::tcp::no_delay(true), ig);
    }
    int err_status = 0;
    std::string err_msg;
    try {
      for (;;) {
        close_after_ = false;
        response_started_ = false;
        Request req = co_await read_request_();
        co_await run_request_(std::move(req));
        if (close_after_) break;
      }
    } catch (const ConnClosed& e) {
      log(LogLevel::Debug, "h1 {} conn closed: {}", id_(), e.ec.message());
    } catch (const RequestError& e) {
      log(LogLevel::Info, "h1 {} request error: {} {}", id_(), e.status, e.msg);
      err_status = e.status;
      err_msg = e.msg;
    } catch (const std::exception& e) {
      log(LogLevel::Error, "h1 {} fatal: {}", id_(), e.what());
    } catch (...) {
      log(LogLevel::Error, "h1 {} fatal: unknown", id_());
    }
    // co_await is illegal inside catch handlers — run it afterwards.
    if (err_status != 0 && !response_started_) {
      try {
        co_await send_simple_(err_status, err_msg);
      } catch (...) {}
    }
    close_socket_();
  }

  // ---- ShutdownTarget -------------------------------------------------------
  void initiate_shutdown() override {
    auto self = this->shared_from_this();
    asio::post(sock_.get_executor(), [self] {
      self->cancel_current_();
      self->close_socket_();
    });
  }

  // ---- ServerHooks ------------------------------------------------------------
  asio::awaitable<void> send_response(HttpCtx& ctx) override {
    Response& r = ctx.res;
    const bool head = (ctx.req.method == "HEAD");
    const bool ka = keep_alive_ && !close_after_;
    std::string out;
    out.reserve(256 + r.body.size());
    out += std::format("HTTP/1.1 {} {}\r\n", r.status, http_status_text(r.status));
    bool explicit_cl = false;
    std::string cl_value;
    for (const auto& [k, v] : r.headers) {
      if (ieq_ascii(k, "content-length")) { explicit_cl = true; cl_value = sanitize_header_value(v); continue; }
      if (ieq_ascii(k, "connection") || ieq_ascii(k, "transfer-encoding") ||
          ieq_ascii(k, "keep-alive") || ieq_ascii(k, "upgrade"))
        continue;
      out += header_line_(k, v);
    }
    out += "content-type: " + sanitize_header_value(r.content_type) + "\r\n";
    out += "content-length: " +
           (explicit_cl ? cl_value : std::to_string(r.body.size())) + "\r\n";
    out += "connection: " + std::string(ka ? "keep-alive" : "close") + "\r\n";
    out += "date: " + http_date_now() + "\r\n";
    out += "server: " + server_id() + "\r\n";
    out += "\r\n";
    if (!head) out += r.body;
    last_status_ = r.status;
    response_started_ = true;
    co_await write_all_(out);
  }

  asio::awaitable<void> begin_stream(
      HttpCtx& ctx, int status, std::string content_type,
      std::vector<std::pair<std::string, std::string>> headers) override {
    ctx.streaming = true;
    ctx.res.status = status;
    // Streaming responses (SSE / large files) end this HTTP/1 connection:
    // keep-alive semantics with a mid-flight stream are a hazard (pipelined
    // requests would have to be discarded). HTTP/2 multiplexes properly.
    close_after_ = true;
    const bool chunked = false;  // we always close after the stream
    auto out = std::make_shared<OutStream>(co_await asio::this_coro::executor,
                                           app_.limits.max_sse_outbox);
    ctx.out = out;
    cur_out_ = out;
    std::string head;
    head.reserve(512);
    head += std::format("HTTP/1.1 {} {}\r\n", status, http_status_text(status));
    head += "content-type: " + sanitize_header_value(content_type) + "\r\n";
    for (const auto& [k, v] : headers) head += header_line_(k, v);
    head += "connection: close\r\n";
    head += "date: " + http_date_now() + "\r\n";
    head += "server: " + server_id() + "\r\n\r\n";
    last_status_ = status;
    response_started_ = true;
    co_await write_all_(head);

    drain_done_ = std::make_shared<Latch>(co_await asio::this_coro::executor);
    auto self = this->shared_from_this();
    asio::co_spawn(sock_.get_executor(),
                   [self, out] -> asio::awaitable<void> {
                     co_await self->drain_(out, chunked);
                   },
                   asio::detached);
    start_read_watcher_(out);
  }

 private:
  struct RegGuard {
    ShutdownRegistry& reg;
    std::shared_ptr<ShutdownTarget> self;
    ~RegGuard() { reg.remove(self); }
  };

  std::string id_() const {
    return remote_.empty() ? std::string("conn") : remote_;
  }

  static std::string header_line_(const std::string& k, const std::string& v) {
    return to_lower_ascii(k) + ": " + sanitize_header_value(v) + "\r\n";
  }

  // ---- low-level I/O ---------------------------------------------------------
  // Whole-request deadline: every read is bounded by min(io_timeout,
  // remaining deadline) so drip-fed (slowloris) requests are cut off even
  // though each individual read completes in time.
  asio::awaitable<void> read_more_(std::chrono::milliseconds to) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        req_deadline_ - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::milliseconds{0})
      throw RequestError{408, "request deadline exceeded"};
    const auto budget = std::min(to, remaining);
    if (rpos_ > 0) {  // compact consumed prefix, keep pipelined tail
      rbuf_.erase(0, rpos_);
      rpos_ = 0;
    }
    char tmp[8192];
    auto [ec, n] = co_await sock_.async_read_some(
        asio::buffer(tmp),
        fw::cancel_after(budget, asio::as_tuple(asio::use_awaitable)));
    if (ec) throw ConnClosed{ec};
    rbuf_.append(tmp, n);
  }

  asio::awaitable<void> write_all_(std::string_view data) {
    auto [ec, n] = co_await asio::async_write(
        sock_, asio::buffer(data),
        fw::cancel_after(app_.limits.io_timeout,
                         asio::as_tuple(asio::use_awaitable)));
    (void)n;
    if (ec) throw ConnClosed{ec};
  }

  void close_socket_() {
    asio::error_code ig;
    if constexpr (std::is_same_v<Stream, asio::ip::tcp::socket>) {
      sock_.close(ig);
    } else {
      sock_.lowest_layer().close(ig);
    }
  }

  // ---- request parsing (hardened) ---------------------------------------------
  asio::awaitable<Request> read_request_() {
    const Limits& lim = app_.limits;
    if (rpos_ > 0) { rbuf_.erase(0, rpos_); rpos_ = 0; }
    req_deadline_ = std::chrono::steady_clock::now() + lim.request_deadline;

    // -- header block with a hard cap (431) ------------------------------------
    std::size_t hdr_end = std::string::npos;
    bool first = true;
    for (;;) {
      hdr_end = rbuf_.find("\r\n\r\n");
      if (hdr_end != std::string::npos) break;
      if (rbuf_.size() > lim.max_header_bytes)
        throw RequestError{431, "request header section too large"};
      co_await read_more_(first ? lim.idle_keepalive : lim.io_timeout);
      first = false;
    }
    const std::string_view block(rbuf_.data(), hdr_end + 4);

    // -- request line -----------------------------------------------------------
    const std::size_t line_end = block.find("\r\n");
    const std::string_view req_line = block.substr(0, line_end);
    const std::size_t sp1 = req_line.find(' ');
    const std::size_t sp2 = req_line.rfind(' ');
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos ||
        sp1 == sp2 || sp1 == 0 || sp2 == req_line.size())
      throw RequestError{400, "malformed request line"};
    {
      const std::string_view method = req_line.substr(0, sp1);
      const std::string_view target = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
      const std::string_view version = req_line.substr(sp2 + 1);
      if (method.empty() || method.size() > 32 || target.empty() ||
          target.size() > 8192 || target.find(' ') != std::string_view::npos)
        throw RequestError{400, "malformed request line"};
      for (const char c : method)
        if (!is_tchar(c)) throw RequestError{400, "invalid method token"};
      Request req;
      req.method = std::string(method);
      req.target = std::string(target);
      req.http_version = 1;
      if (version == "HTTP/1.1") {
        req.keep_alive = true;
      } else if (version == "HTTP/1.0") {
        req.keep_alive = false;
      } else {
        throw RequestError{505, "only HTTP/1.0 and HTTP/1.1 are supported"};
      }

      // -- headers ---------------------------------------------------------------
      bool has_cl = false;
      std::uint64_t cl_value = 0;
      bool te_chunked = false;
      bool expect_continue = false;
      std::size_t count = 0;
      std::size_t pos = line_end + 2;
      bool conn_close = false, conn_ka = false;
      for (;;) {
        const std::size_t eol = block.find("\r\n", pos);
        if (eol == std::string_view::npos) break;
        const std::string_view line = block.substr(pos, eol - pos);
        pos = eol + 2;
        if (line.empty()) break;  // end of headers
        if (++count > lim.max_headers)
          throw RequestError{431, "too many header fields"};
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0)
          throw RequestError{400, "malformed header line"};
        const std::string_view name = line.substr(0, colon);
        for (const char c : name)
          if (!is_tchar(c)) throw RequestError{400, "invalid header name"};
        const std::string_view value = trim_ows(line.substr(colon + 1));
        const std::string lname = to_lower_ascii(name);
        if (lname == "content-length") {
          if (has_cl)
            throw RequestError{400, "duplicate Content-Length"};  // smuggling
          has_cl = true;
          auto n = parse_num<std::uint64_t>(value);
          if (!n) throw RequestError{400, "invalid Content-Length"};
          cl_value = *n;
        } else if (lname == "transfer-encoding") {
          const std::string tv = to_lower_ascii(value);
          if (te_chunked) throw RequestError{400, "duplicate Transfer-Encoding"};
          if (tv != "chunked")
            throw RequestError{501, "unsupported Transfer-Encoding"};
          te_chunked = true;
        } else if (lname == "connection") {
          std::string_view tok = value;
          while (!tok.empty()) {
            const std::size_t comma = tok.find(',');
            const std::string_view part = trim_ows(
                tok.substr(0, comma == std::string_view::npos
                                    ? std::string_view::npos
                                    : comma));
            const std::string lp = to_lower_ascii(part);
            if (lp == "close") conn_close = true;
            if (lp == "keep-alive") conn_ka = true;
            if (comma == std::string_view::npos) break;
            tok.remove_prefix(comma + 1);
          }
        } else if (lname == "expect") {
          if (to_lower_ascii(value).find("100-continue") != std::string::npos)
            expect_continue = true;
        }
        req.headers[lname] = std::string(value);  // lower-cased keys
      }
      if (te_chunked && has_cl)
        throw RequestError{400,
                           "both Content-Length and Transfer-Encoding"};  // smuggling
      if (req.keep_alive && !req.headers.contains("host"))
        throw RequestError{400, "missing Host header"};
      req.keep_alive = req.keep_alive ? !conn_close : conn_ka;

      // Advance the read cursor past the header block (the view above stays
      // valid until the next read_more_ compaction, which cannot happen
      // before the body has been consumed).
      rpos_ = hdr_end + 4;

      // -- target → path/query ------------------------------------------------------
      if (auto err = init_request_target(req))
        throw RequestError{err->first, err->second};

      // Route-specific body cap (checked before the body is read).
      const std::size_t body_limit =
          app_.body_limit_for(req.method, req.path);

      // -- body -----------------------------------------------------------------
      if (expect_continue && (has_cl ? cl_value > 0 : te_chunked))
        co_await write_all_("HTTP/1.1 100 Continue\r\n\r\n");
      if (te_chunked) {
        req.body = co_await read_body_chunked_(body_limit);
      } else if (cl_value > 0) {
        if (cl_value > body_limit)
          throw RequestError{413, "request body too large"};
        while (rbuf_.size() - rpos_ < cl_value)
          co_await read_more_(lim.io_timeout);
        req.body.assign(rbuf_, rpos_, static_cast<std::size_t>(cl_value));
        rpos_ += static_cast<std::size_t>(cl_value);
      }

      // -- peer identity ----------------------------------------------------------
      fill_remote_(req);
      req.tls = tls_;
      req.alpn = alpn_;
      keep_alive_ = req.keep_alive;
      co_return req;
    }
    throw RequestError{400, "unreachable"};  // silence control-flow warnings
  }

  asio::awaitable<std::string> read_body_chunked_(std::size_t body_limit) {
    const Limits& lim = app_.limits;
    std::string body;
    for (;;) {
      const std::string line = co_await read_line_(160, lim.io_timeout);
      std::string_view hex = line;
      if (const auto semi = hex.find(';'); semi != std::string_view::npos)
        hex = hex.substr(0, semi);  // ignore chunk extensions
      if (hex.empty() || hex.size() > 16)
        throw RequestError{400, "invalid chunk size"};
      std::size_t sz = 0;
      for (const char c : hex) {
        auto v = [](char h) -> int {
          if (h >= '0' && h <= '9') return h - '0';
          if (h >= 'a' && h <= 'f') return h - 'a' + 10;
          if (h >= 'A' && h <= 'F') return h - 'A' + 10;
          return -1;
        };
        const int d = v(c);
        if (d < 0) throw RequestError{400, "invalid chunk size"};
        if (sz > (std::numeric_limits<std::size_t>::max() - unsigned(d)) / 16)
          throw RequestError{400, "chunk size overflow"};
        sz = sz * 16 + unsigned(d);
      }
      if (sz == 0) {
        // trailers until empty line (bounded)
        std::size_t total = 0;
        for (int i = 0; i < 64; ++i) {
          const std::string t = co_await read_line_(1024, lim.io_timeout);
          if (t.empty()) break;
          total += t.size();
          if (total > 4096) throw RequestError{431, "trailers too large"};
        }
        co_return body;
      }
      if (body.size() + sz > body_limit)
        throw RequestError{413, "request body too large"};
      while (rbuf_.size() - rpos_ < sz + 2)
        co_await read_more_(lim.io_timeout);
      body.append(rbuf_, rpos_, sz);
      rpos_ += sz;
      if (rbuf_.compare(rpos_, 2, "\r\n") != 0)
        throw RequestError{400, "malformed chunk terminator"};
      rpos_ += 2;
    }
  }

  asio::awaitable<std::string> read_line_(std::size_t cap,
                                          std::chrono::milliseconds to) {
    for (;;) {
      const std::size_t nl = rbuf_.find("\r\n", rpos_);
      if (nl != std::string::npos) {
        if (nl - rpos_ > cap) throw RequestError{400, "line too long"};
        std::string line = rbuf_.substr(rpos_, nl - rpos_);
        rpos_ = nl + 2;
        co_return line;
      }
      if (rbuf_.size() - rpos_ > cap) throw RequestError{400, "line too long"};
      co_await read_more_(to);
    }
  }

  void fill_remote_(Request& req) {
    asio::error_code ec;
    auto ep = [&] {
      if constexpr (std::is_same_v<Stream, asio::ip::tcp::socket>)
        return sock_.remote_endpoint(ec);
      else
        return sock_.lowest_layer().remote_endpoint(ec);
    }();
    if (!ec) {
      req.remote_addr = ep.address().to_string();
      req.remote_port = ep.port();
      remote_ = std::format("{}:{}", req.remote_addr, req.remote_port);
    }
  }

  // ---- per-request execution ----------------------------------------------------
  asio::awaitable<void> run_request_(Request req) {
    const auto t0 = std::chrono::steady_clock::now();
    HttpCtx ctx;
    ctx.req = std::move(req);
    ctx.hooks = this;
    auto sig = std::make_shared<asio::cancellation_signal>();
    cur_cancel_ = sig.get();
    const std::string log_line = std::format(
        "h1 {} {} {}", ctx.req.method, ctx.req.path, remote_);

    asio::error_code fail_ec;
    bool failed = false;
    int err_status = 0;
    std::string err_msg;
    try {
      co_await asio::co_spawn(
          co_await asio::this_coro::executor,
          [&ctx, this]() -> asio::awaitable<void> { co_await app_.dispatch(ctx); },
          asio::bind_cancellation_slot(sig->slot(), asio::use_awaitable));
      if (!ctx.streaming) {
        if (ctx.res.status < 100 || ctx.res.status > 599) ctx.res.status = 500;
        co_await send_response(ctx);
      }
      // For streamed responses the drain coroutine owns the wire; it latches
      // below. After a stream the connection always closes (see begin_stream).
    } catch (const RequestError& e) {
      failed = true;
      err_status = e.status;
      err_msg = e.msg;
      close_after_ = true;
    } catch (const ConnClosed& e) {
      failed = true;
      fail_ec = e.ec;
      close_after_ = true;
    } catch (const asio::system_error& e) {
      failed = true;  // cancelled (client gone) or IO error
      fail_ec = e.code();
      if (ctx.out && !ctx.out->closed()) ctx.out->close();
      close_after_ = true;
    } catch (const std::exception& e) {
      failed = true;
      log(LogLevel::Error, "h1 handler error: {}", e.what());
      err_status = 500;
      err_msg = "internal server error";
      close_after_ = true;
    }
    cur_cancel_ = nullptr;

    // co_await is illegal inside catch handlers — error pages go out here.
    if (err_status != 0 && !ctx.streaming && !response_started_) {
      try {
        co_await send_simple_(err_status, err_msg);
      } catch (const ConnClosed& c) {
        fail_ec = c.ec;
      }
    }

    if (ctx.streaming && drain_done_) {
      if (ctx.out && !ctx.out->closed()) ctx.out->finish();  // graceful if still open
      co_await drain_done_->wait();
      drain_done_.reset();
    }

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    if (failed)
      log(LogLevel::Info, "{} → {} ({} ms) [{}]", log_line, last_status_, ms,
          fail_ec.message());
    else
      log(LogLevel::Info, "{} → {} ({} ms)", log_line, last_status_, ms);
  }

  asio::awaitable<void> send_simple_(int status, std::string_view msg) {
    Response r = Response::html_page(status, http_status_text(status), msg);
    HttpCtx ctx;
    ctx.req.method = "GET";  // minimal context for the serializer
    ctx.hooks = this;
    ctx.res = std::move(r);
    co_await send_response(ctx);
  }

  // ---- streaming machinery -----------------------------------------------------
  // Single writer for the streaming phase: the only coroutine allowed to
  // touch the socket while a stream response is in flight.
  asio::awaitable<void> drain_(std::shared_ptr<OutStream> out, bool chunked) {
    bool graceful = false;
    try {
      while (auto chunk = co_await out->receive()) {
        if (chunk->empty()) { graceful = true; break; }  // finish sentinel
        if (chunked) {
          std::string frame;
          frame.reserve(chunk->size() + 32);
          frame += std::format("{:x}\r\n", chunk->size());
          frame += *chunk;
          frame += "\r\n";
          co_await write_all_(frame);
        } else {
          co_await write_all_(*chunk);
        }
      }
      if (graceful && chunked) co_await write_all_("0\r\n\r\n");
    } catch (...) {
      // conn died mid-stream — fall through to abort
    }
    out->mark_drained_and_close();
    if (drain_done_) drain_done_->hit();
  }

  // While the request handler streams, nobody reads the socket. This watcher
  // detects client disconnects (EOF/RST) and cancels the handler.
  void start_read_watcher_(const std::shared_ptr<OutStream>& out) {
    auto self = this->shared_from_this();
    asio::co_spawn(sock_.get_executor(),
                   [self, out] -> asio::awaitable<void> {
      char dump[1024];
      for (;;) {
        auto [ec, n] = co_await self->sock_.async_read_some(
            asio::buffer(dump), asio::as_tuple(asio::use_awaitable));
        if (ec) {  // eof / reset / closed
          out->close();
          self->cancel_current_();
          co_return;
        }
        (void)n;  // unexpected bytes during a stream are discarded
      }
    }, asio::detached);
  }

  void cancel_current_() {
    if (cur_cancel_) cur_cancel_->emit(asio::cancellation_type::terminal);
  }

  // ---- state -----------------------------------------------------------------
  Stream sock_;
  App& app_;
  ShutdownRegistry& reg_;
  std::string rbuf_;
  std::size_t rpos_ = 0;
  bool tls_;
  std::string alpn_;
  std::string remote_;
  bool keep_alive_ = true;
  bool close_after_ = false;
  bool response_started_ = false;
  int last_status_ = 0;
  std::chrono::steady_clock::time_point req_deadline_{};
  asio::cancellation_signal* cur_cancel_ = nullptr;
  std::shared_ptr<OutStream> cur_out_;
  std::shared_ptr<Latch> drain_done_;
};

}  // namespace h1
}  // namespace fw
