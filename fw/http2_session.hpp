// ============================================================================
// fw/http2_session.hpp — HTTP/2 session on the from-scratch engine
// (fw/h2_conn.hpp + fw/h2_hpack.hpp + fw/h2_frame.hpp — pure C++26, no
// nghttp2): multiplexed streams, HPACK, flow control, per-stream outbound
// queues with high/low watermarks, GOAWAY shutdown.
//
//   Concurrency model (unchanged from the nghttp2 edition)
//   ------------------------------------------------------
//   * One strand per connection. The engine is touched only on that strand
//     (read loop, pump, drain coroutines, runner coroutines).
//   * Exactly one coroutine writes to the socket (pump_), fed by a
//     single-slot notification channel; everything else only queues into
//     the engine + notify_write().
//   * Engine events fire synchronously from feed()/produce(); anything that
//     would resume a coroutine (cancels, spawns) is deferred via
//     pending_cancel_ / asio::post — never inline from an event.
// ===========================================================================
#pragma once

#if FW_HTTP2

#include "fw/detail/base.hpp"
#include "fw/util.hpp"
#include "fw/message.hpp"
#include "fw/limits.hpp"
#include "fw/latch.hpp"
#include "fw/out_stream.hpp"
#include "fw/hooks.hpp"
#include "fw/app.hpp"
#include "fw/shutdown.hpp"
#include "fw/h2_conn.hpp"

namespace fw::h2 {

// Per-stream record (session side). The outbound byte stream lives in the
// engine's per-stream queue; the session mirrors what the handler needs:
// the request, its limits, the SSE OutStream and its pacing primitives.
// The cancellation signal is embedded (not make_shared) — the record is
// already shared_ptr-managed, and pending_cancel_ keeps whole records alive
// until their deferred emit.
struct H2StreamRec {
  std::uint32_t id = 0;
  Request req;
  std::size_t hdr_bytes = 0;
  std::size_t body_bytes = 0;
  std::size_t body_limit = 0;     // route-specific cap (set once :path is known)
  bool headers_done = false;      // saw a regular (non-pseudo) header
  bool dispatched = false;
  bool dead = false;              // stream closed (RST / error)
  bool response_sent = false;
  asio::cancellation_signal cancel_sig;  // emitted after close (deferred)
  std::shared_ptr<OutStream> out;
  std::shared_ptr<Latch> drain_done;
  // Signalled by the engine when the send queue drains to empty; the drain
  // coroutine waits on it above the high-water mark. This yields the strand
  // to the pump and bounds in-flight bytes per stream.
  std::unique_ptr<asio::experimental::concurrent_channel<void(asio::error_code)>> room;
};

template <class Stream>
class Http2Session final : public ServerHooks,
                           public H2ConnEvents,
                           public ShutdownTarget,
                           public std::enable_shared_from_this<Http2Session<Stream>> {
 public:
  Http2Session(Stream sock, App& app, ShutdownRegistry& reg, std::string prefeed,
               bool tls, std::string alpn)
      : sock_(std::move(sock)),
        app_(app),
        reg_(reg),
        prefeed_(std::move(prefeed)),
        tls_(tls),
        alpn_(std::move(alpn)),
        eng_(make_limits_(), *this),
        write_sig_(sock_.get_executor(), 1),
        pump_done_(sock_.get_executor()) {}

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
    remote_ = remote_of_();

    eng_.start();
    notify_write_();
    // writer coroutine (single socket writer for this connection)
    asio::co_spawn(sock_.get_executor(),
                   [self] -> asio::awaitable<void> { co_await self->pump_(); },
                   asio::detached);

    // If the connection preface was pre-read during protocol detection,
    // feed it first (the engine validates the 24 magic bytes itself).
    bool read_failed = false;
    if (!prefeed_.empty()) {
      read_failed = !eng_.feed(prefeed_.data(), prefeed_.size());
      if (read_failed) log(LogLevel::Warn, "h2 {}: bad preface", id_());
      prefeed_.clear();
      flush_pending_cancels_();
      notify_write_();
    }

    // read loop (bounded by the no-progress deadline)
    progress_deadline_ = std::chrono::steady_clock::now() + app_.limits.h2_idle_timeout;
    std::string buf(16384, '\0');
    while (!read_failed) {
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          progress_deadline_ - std::chrono::steady_clock::now());
      if (remaining <= std::chrono::milliseconds{0}) {
        log(LogLevel::Info, "h2 {}: no-progress deadline (slowloris?)", id_());
        eng_.submit_goaway(frame::kEnhanceYourCalm);
        break;
      }
      const auto budget = std::min(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              app_.limits.h2_idle_timeout),
          remaining);
      auto [ec, n] = co_await sock_.async_read_some(
          asio::buffer(buf),
          fw::cancel_after(budget, asio::as_tuple(asio::use_awaitable)));
      if (ec) {
        if (ec == asio::error::operation_aborted)
          log(LogLevel::Info, "h2 {}: idle timeout", id_());
        else
          log(LogLevel::Debug, "h2 {}: read loop end: {}", id_(), ec.message());
        break;
      }
      if (!eng_.feed(buf.data(), n)) {
        log(LogLevel::Warn, "h2 {}: protocol error", id_());
        break;
      }
      flush_pending_cancels_();
      notify_write_();
    }

    // Reap live streams (SSE handlers would otherwise never wake and chat
    // users would stay "online" as ghosts), then GOAWAY + flush + close.
    close_all_streams_();
    eng_.submit_goaway(frame::kNoError);  // clean GOAWAY (no-op if fatal)
    flush_pending_cancels_();
    write_sig_.close();
    co_await pump_done_.wait();
    close_socket_();
  }

  // ---- ShutdownTarget ----------------------------------------------------
  void initiate_shutdown() override {
    auto self = this->shared_from_this();
    asio::post(sock_.get_executor(), [self] {
      self->eng_.submit_goaway(frame::kNoError);  // send GOAWAY
      self->notify_write_();
      // Give the pump a moment to flush it, then force the parked read out
      // (the read loop then runs the same close_all_streams_() cleanup).
      auto t = std::make_shared<asio::steady_timer>(self->sock_.get_executor());
      t->expires_after(std::chrono::milliseconds(500));
      t->async_wait([self, t](asio::error_code) { self->close_socket_(); });
    });
  }

  // ---- ServerHooks ------------------------------------------------------------
  asio::awaitable<void> send_response(HttpCtx& ctx) override {
    auto* rec = static_cast<H2StreamRec*>(ctx.per_request);
    if (!rec || rec->dead) co_return;
    Response& r = ctx.res;
    const bool head = (ctx.req.method == "HEAD");
    char nb[24];
    hreset_();
    {
      auto [p, ec] = std::to_chars(nb, nb + sizeof(nb), r.status);
      status_val_.assign(nb, std::size_t(p - nb));
    }
    hput_(":status", status_val_);
    bool explicit_cl = false;
    for (const auto& [k, v] : r.headers) {
      if (ieq_ascii(k, "content-length")) {
        explicit_cl = true;
        hput_("content-length", v);
        continue;
      }
      if (ieq_ascii(k, "connection") || ieq_ascii(k, "transfer-encoding") ||
          ieq_ascii(k, "keep-alive") || ieq_ascii(k, "upgrade") ||
          ieq_ascii(k, "proxy-connection"))
        continue;  // connection-specific headers are illegal in h2
      hput_(k, v);
    }
    hput_("content-type", r.content_type);
    if (!explicit_cl) {
      auto [p, ec] = std::to_chars(nb, nb + sizeof(nb), r.body.size());
      status_val_.assign(nb, std::size_t(p - nb));
      hput_("content-length", status_val_);
    }
    hput_("date", http_date_now());
    hput_("server", server_id());
    hbind_nva_();

    if (head || r.body.empty()) {
      eng_.submit_response(rec->id, nva_, /*end_stream=*/true);
    } else {
      // Open HEADERS (no END_STREAM), then the body as DATA frames whose
      // last one carries END_STREAM (EOF after the queue drains).
      eng_.submit_response(rec->id, nva_, /*end_stream=*/false);
      eng_.submit_data(rec->id, std::move(r.body), /*end_after=*/true);
    }
    rec->response_sent = true;
    last_status_ = r.status;
    notify_write_();
    co_return;
  }

  asio::awaitable<void> begin_stream(
      HttpCtx& ctx, int status, std::string content_type,
      std::vector<std::pair<std::string, std::string>> headers) override {
    auto* rec0 = static_cast<H2StreamRec*>(ctx.per_request);
    if (!rec0 || !streams_.count(rec0->id) || rec0->dead) {
      // stream died while the handler was starting — hand back a dead stream
      ctx.streaming = true;
      auto dead = std::make_shared<OutStream>(co_await asio::this_coro::executor, 1);
      dead->close();
      ctx.out = dead;
      co_return;
    }
    auto rec = streams_[rec0->id];
    ctx.streaming = true;
    ctx.res.status = status;

    hreset_();
    {
      char nb[24];
      auto [p, ec] = std::to_chars(nb, nb + sizeof(nb), status);
      status_val_.assign(nb, std::size_t(p - nb));
    }
    hput_(":status", status_val_);
    for (const auto& [k, v] : headers) {
      if (ieq_ascii(k, "connection") || ieq_ascii(k, "transfer-encoding") ||
          ieq_ascii(k, "content-length"))
        continue;
      hput_(k, v);
    }
    hput_("content-type", content_type);
    hput_("date", http_date_now());
    hput_("server", server_id());
    hbind_nva_();

    // Open the stream: HEADERS *without* END_STREAM — data follows as DATA
    // frames. (END_STREAM here would close the stream immediately, which
    // would be wrong for SSE.)
    eng_.submit_response(rec->id, nva_, /*end_stream=*/false);
    rec->response_sent = true;
    last_status_ = status;

    rec->out = std::make_shared<OutStream>(co_await asio::this_coro::executor,
                                           app_.limits.max_sse_outbox);
    rec->drain_done = std::make_shared<Latch>(co_await asio::this_coro::executor);
    rec->room = std::make_unique<
        asio::experimental::concurrent_channel<void(asio::error_code)>>(
        co_await asio::this_coro::executor, 1);
    ctx.out = rec->out;
    notify_write_();

    auto self = this->shared_from_this();
    asio::post(sock_.get_executor(), [self, rec] {
      asio::co_spawn(self->sock_.get_executor(),
                     [self, rec] -> asio::awaitable<void> {
                       co_await self->stream_drain_(rec);
                     },
                     asio::detached);
    });
  }

  // ---- H2ConnEvents (engine → session; all on the strand, all sync) --------
  bool on_begin_request(std::uint32_t id) override {
    // goaway already received → do not accept new work (mirrors the old
    // REFUSED-at-dispatch behavior, but earlier).
    if (eng_.goaway_received()) return false;
    auto rec = std::make_shared<H2StreamRec>();
    rec->id = id;
    rec->body_limit = app_.limits.max_body_bytes;  // refined at HEADERS end
    streams_.emplace(id, std::move(rec));
    return true;
  }

  void on_header(std::uint32_t id, std::string_view n,
                 std::string_view v) override {
    auto* rec = find_(id);
    if (!rec || rec->dispatched || rec->dead) return;
    if (n.empty()) return;
    if (n[0] == ':') {
      if (rec->headers_done) return;  // pseudo after regular → refuse? keep first
      if (n == ":method") rec->req.method.assign(v);
      else if (n == ":path") rec->req.target.assign(v);
      else if (n == ":authority") rec->req.set_header("host", std::string(v));
      else if (n == ":scheme") { /* unused */ }
      return;
    }
    rec->headers_done = true;
    if (rec->req.headers.size() >= app_.limits.max_headers ||
        rec->hdr_bytes + n.size() + v.size() > app_.limits.max_header_bytes) {
      eng_.submit_rst(id, frame::kEnhanceYourCalm);
      return;
    }
    rec->hdr_bytes += n.size() + v.size();
    rec->req.set_header(to_lower_ascii(n), std::string(v));
  }

  void on_headers_end(std::uint32_t id, bool end_stream,
                      bool trailers) override {
    auto* rec = find_(id);
    if (!rec || rec->dispatched || rec->dead || trailers) {
      if (rec && trailers && !rec->dispatched && end_stream) maybe_dispatch_(id);
      return;
    }
    // Header block complete (incl. CONTINUATION): the target is known —
    // refine the body limit before any DATA can arrive.
    probe_.method.assign(rec->req.method);
    probe_.target.assign(rec->req.target);
    probe_.query.clear();
    if (!init_request_target(probe_))
      rec->body_limit = app_.body_limit_for(probe_.method, probe_.path);
    // "expect: 100-continue" — answer early so the client does not sit out
    // its timeout before sending the body.
    if (!end_stream) {
      if (const std::string* e = rec->req.header("expect");
          e && to_lower_ascii(*e).find("100-continue") != std::string::npos) {
        eng_.submit_response(id, {{":status", "100"}}, /*end_stream=*/false);
        notify_write_();
      }
    }
  }

  bool on_data(std::uint32_t id, std::string_view payload) override {
    auto* rec = find_(id);
    if (!rec || rec->dispatched || rec->dead) return true;  // consume & credit
    if (rec->body_bytes + payload.size() > rec->body_limit) {
      log(LogLevel::Info, "h2 stream {}: body too large", id);
      eng_.submit_rst(id, frame::kEnhanceYourCalm);
      return false;  // engine returns credit only
    }
    rec->body_bytes += payload.size();
    rec->req.body.append(payload);
    return true;
  }

  void on_end_stream(std::uint32_t id) override { maybe_dispatch_(id); }

  void on_stream_close(std::uint32_t id, std::uint32_t error_code) override {
    const auto it = streams_.find(id);
    if (it == streams_.end()) return;  // already reaped by us
    auto rec = it->second;
    streams_.erase(it);
    if (rec->dispatched) live_dispatched_--;
    rec->dead = true;
    if (rec->out) rec->out->close();          // wake handler + drain
    pending_cancel_.push_back(rec);           // emit after we leave the engine
    if (error_code != frame::kNoError)
      log(LogLevel::Debug, "h2 stream {} closed: {}", id, error_code);
  }

  void on_goaway() override {}
  void on_progress() override {
    // Any complete inbound frame is "progress": pushes the drip-feed
    // (slowloris) deadline forward. Idle-but-active SSE connections stay
    // alive through the client's WINDOW_UPDATE / PING frames.
    progress_deadline_ =
        std::chrono::steady_clock::now() + app_.limits.h2_idle_timeout;
  }
  void on_sendq_empty(std::uint32_t id) override {
    if (auto* rec = find_(id); rec && rec->room)
      rec->room->try_send(asio::error_code{});
  }

 private:
  struct RegGuard {
    ShutdownRegistry& reg;
    std::shared_ptr<ShutdownTarget> self;
    ~RegGuard() { reg.remove(self); }
  };

  H2EngineLimits make_limits_() const {
    H2EngineLimits e;
    e.max_concurrent_streams =
        std::uint32_t(app_.limits.max_h2_streams);
    e.max_header_count = app_.limits.max_headers;
    e.max_header_bytes = app_.limits.max_header_bytes;
    e.recv_initial_window = 1u << 20;  // 1 MiB per stream (as before)
    e.recv_conn_window = 1u << 20;     // 1 MiB connection window
    e.max_frame_size = frame::kMaxFrameDefault;
    return e;
  }

  std::string id_() const { return remote_; }

  std::string remote_of_() {
    asio::error_code ec;
    auto ep = [&] {
      if constexpr (std::is_same_v<Stream, asio::ip::tcp::socket>)
        return sock_.remote_endpoint(ec);
      else
        return sock_.lowest_layer().remote_endpoint(ec);
    }();
    return ec ? "conn" : ep.address().to_string() + ":" +
                             std::to_string(ep.port());
  }

  void close_all_streams_() {
    if (streams_.empty()) return;
    std::vector<std::shared_ptr<H2StreamRec>> cancels;
    cancels.reserve(streams_.size());
    for (auto& [id, rec] : streams_) {
      rec->dead = true;
      if (rec->dispatched) --live_dispatched_;
      if (rec->out) rec->out->close();  // wake SSE handler → hub detach
      cancels.push_back(rec);
      log(LogLevel::Debug, "h2 reaping stream {} (session end)", id);
    }
    streams_.clear();
    pending_cancel_.insert(
        pending_cancel_.end(), std::make_move_iterator(cancels.begin()),
        std::make_move_iterator(cancels.end()));
  }

  void close_socket_() {
    asio::error_code ig;
    if constexpr (std::is_same_v<Stream, asio::ip::tcp::socket>) {
      sock_.close(ig);
    } else {
      sock_.lowest_layer().close(ig);
    }
  }

  void notify_write_() { write_sig_.try_send(asio::error_code{}); }

  H2StreamRec* find_(std::uint32_t id) {
    const auto it = streams_.find(id);
    return it == streams_.end() ? nullptr : it->second.get();
  }

  // ---- response-header serialization scratch ----------------------------------
  // hstore_ entries are reused by assignment (clear() would destroy the
  // strings' capacity): a warm connection serializes response headers with
  // zero heap traffic. nva_ re-binds views over the live prefix every time.
  struct HEntry {
    std::string k, v;
  };
  std::vector<HEntry> hstore_;
  std::size_t hcount_ = 0;
  std::vector<std::pair<std::string_view, std::string_view>> nva_;
  std::string status_val_;  // ":status" / "content-length" number scratch
  Request probe_;           // reused body-limit probe (on_headers_end)

  void hreset_() { hcount_ = 0; }

  void hput_(std::string_view k, std::string_view v) {
    HEntry* e;
    if (hcount_ < hstore_.size()) {
      e = &hstore_[hcount_];
    } else {
      hstore_.emplace_back();
      e = &hstore_.back();
    }
    e->k.clear();
    e->v.clear();
    append_lower_ascii(e->k, k);   // names lower-cased (as before)
    append_sanitized(e->v, v);     // CR/LF/NUL stripped (as before)
    ++hcount_;
  }

  void hbind_nva_() {
    nva_.clear();
    for (std::size_t i = 0; i < hcount_; ++i)
      nva_.emplace_back(hstore_[i].k, hstore_[i].v);
  }

  void flush_pending_cancels_() {
    if (pending_cancel_.empty()) return;
    for (auto& rec : pending_cancel_)
      rec->cancel_sig.emit(asio::cancellation_type::terminal);
    pending_cancel_.clear();
  }

  // ---- request dispatch ------------------------------------------------------
  void maybe_dispatch_(std::uint32_t id) {
    auto* rec = find_(id);
    if (!rec) return;
    if (rec->dispatched || rec->dead) return;

    // finalize the request (shared target parsing)
    rec->req.http_version = 2;
    rec->req.h2_stream_id = int(id);
    if (auto err = init_request_target(rec->req)) {
      submit_error_(rec, err->first, err->second);
      return;
    }
    {
      asio::error_code ec;
      auto ep = [&] {
        if constexpr (std::is_same_v<Stream, asio::ip::tcp::socket>)
          return sock_.remote_endpoint(ec);
        else
          return sock_.lowest_layer().remote_endpoint(ec);
      }();
      if (!ec) {
        rec->req.remote_addr = ep.address().to_string();
        rec->req.remote_port = ep.port();
      }
    }
    rec->req.tls = tls_;
    rec->req.alpn = alpn_;
    rec->req.keep_alive = true;
    if (eng_.goaway_received()) {
      eng_.submit_rst(id, frame::kRefusedStream);
      return;
    }
    auto selfsp = this->shared_from_this();
    auto recsp = streams_.count(id) ? streams_[id] : nullptr;
    if (!recsp) return;
    rec->dispatched = true;
    ++live_dispatched_;
    // Post the spawn: never start the handler inline inside an engine event.
    asio::post(sock_.get_executor(), [selfsp, recsp] {
      asio::co_spawn(selfsp->sock_.get_executor(),
                     [selfsp, recsp] -> asio::awaitable<void> {
                       co_await selfsp->stream_runner_(recsp);
                     },
                     asio::bind_cancellation_slot(recsp->cancel_sig.slot(),
                                                  asio::detached));
    });
  }

  void submit_error_(H2StreamRec* rec, int status, const std::string& msg) {
    Response r = Response::json_error(status, msg);
    char nb[24];
    hreset_();
    {
      auto [p, ec] = std::to_chars(nb, nb + sizeof(nb), r.status);
      status_val_.assign(nb, std::size_t(p - nb));
    }
    hput_(":status", status_val_);
    hput_("content-type", r.content_type);
    {
      auto [p, ec] = std::to_chars(nb, nb + sizeof(nb), r.body.size());
      status_val_.assign(nb, std::size_t(p - nb));
      hput_("content-length", status_val_);
    }
    hput_("server", server_id());
    hbind_nva_();
    eng_.submit_response(rec->id, nva_, /*end_stream=*/false);
    eng_.submit_data(rec->id, std::move(r.body), /*end_after=*/true);
    rec->response_sent = true;
    rec->dispatched = true;   // never dispatch this stream again
    last_status_ = status;
    notify_write_();
  }

  asio::awaitable<void> stream_runner_(std::shared_ptr<H2StreamRec> rec) {
    const auto t0 = std::chrono::steady_clock::now();
    HttpCtx ctx;
    ctx.req = std::move(rec->req);
    ctx.per_request = rec.get();
    ctx.hooks = this;
    bool failed = false;
    std::string fail_msg;
    try {
      co_await app_.dispatch(ctx);
      if (!ctx.streaming) {
        if (ctx.res.status < 100 || ctx.res.status > 599) ctx.res.status = 500;
        co_await send_response(ctx);
      }
    } catch (const asio::system_error& e) {
      failed = true;  // cancelled (client RST / GOAWAY / shutdown) or IO error
      fail_msg = e.code().message();
      if (ctx.out && !ctx.out->closed()) ctx.out->close();
    } catch (const std::exception& e) {
      failed = true;
      fail_msg = e.what();
      log(LogLevel::Error, "h2 handler error (stream {}): {}", rec->id, e.what());
      if (ctx.streaming && ctx.out && !ctx.out->closed()) {
        ctx.out->close();
      } else if (!ctx.streaming && !rec->dead && !rec->response_sent) {
        submit_error_(rec.get(), 500, "internal server error");
      }
    }
    if (ctx.streaming && rec->drain_done) {
      if (ctx.out && !ctx.out->closed()) ctx.out->finish();
      co_await rec->drain_done->wait();
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    log(failed ? LogLevel::Warn : LogLevel::Info,
        "h2 {} {} stream {} → {} ({} ms){}", ctx.req.method, ctx.req.path,
        rec->id, last_status_, ms,
        failed ? " [" + fail_msg + "]" : std::string{});
  }

  // Single writer for one h2 stream: consumes the OutStream channel and
  // feeds the engine's per-stream queue, honoring the finish sentinel.
  asio::awaitable<void> stream_drain_(std::shared_ptr<H2StreamRec> rec) {
    bool overflow = false;
    while (auto chunk = co_await rec->out->receive()) {
      if (chunk->empty()) break;  // finish sentinel → graceful EOF below
      if (rec->dead) break;
      if (eng_.queued_bytes(rec->id) + chunk->size() >
          app_.limits.max_h2_stream_buffer) {
        overflow = true;
        break;
      }
      eng_.submit_data(rec->id, std::move(*chunk), /*end_after=*/false);
      notify_write_();
      // High/low-water pacing: pause so the pump can drain the queue.
      // Without this, the drain would pull the whole channel into the
      // engine without ever yielding the strand.
      while (!rec->dead && rec->room &&
             eng_.queued_bytes(rec->id) >= app_.limits.h2_sendq_high_water) {
        auto [wec] = co_await rec->room->async_receive(
            fw::cancel_after(std::chrono::seconds(5),
                             asio::as_tuple(asio::use_awaitable)));
        (void)wec;  // token, timeout or closed — re-check the condition
      }
    }
    if (overflow && !rec->dead) {
      log(LogLevel::Warn, "h2 stream {}: send buffer overflow", rec->id);
      eng_.submit_rst(rec->id, frame::kEnhanceYourCalm);
    } else if (!rec->dead) {
      eng_.submit_data(rec->id, {}, /*end_after=*/true);  // END_STREAM
      notify_write_();
    }
    rec->out->mark_drained_and_close();
    if (rec->drain_done) rec->drain_done->hit();
  }

  // ---- connection writer ------------------------------------------------------
  asio::awaitable<void> pump_() {
    // The write buffer must stay alive across the co_await: the engine's
    // `out_` may be appended to (and reallocated!) by other coroutines
    // while a write is in flight, so we copy into a stable local first.
    std::string outbuf;
    for (;;) {
      auto [ec] = co_await write_sig_.async_receive(
          asio::as_tuple(asio::use_awaitable));
      if (ec) break;  // channel closed → final flush and exit
      bool io_failed = false;
      for (;;) {
        eng_.produce();  // no-op if everything is already serialized
        if (eng_.output().empty()) {
          // Nothing flushable: either fully drained or DATA deferred by
          // flow windows — wait for the next token (WINDOW_UPDATE etc.).
          break;
        }
        outbuf.assign(eng_.output());
        auto [wec, n] = co_await asio::async_write(
            sock_, asio::buffer(outbuf),
            fw::cancel_after(app_.limits.io_timeout,
                             asio::as_tuple(asio::use_awaitable)));
        if (wec) { io_failed = true; break; }
        eng_.consume(n);
        // Liveness: an SSE stream's keepalive comment (server→client DATA
        // every 15 s) may not provoke any inbound frame for a long time —
        // the browser's flow-control windows are large. If live dispatched
        // streams exist, our own successful writes push the no-progress
        // (slowloris) deadline forward; incomplete request streams keep
        // the strict inbound deadline.
        if (live_dispatched_ > 0)
          progress_deadline_ = std::chrono::steady_clock::now() +
                               app_.limits.h2_idle_timeout;
      }
      if (io_failed) break;
      flush_pending_cancels_();  // close events may have fired in produce()
    }
    // final flush attempt (e.g. the GOAWAY produced at shutdown)
    if (eng_.want_write() || !eng_.output().empty()) {
      eng_.produce();
      if (!eng_.output().empty()) {
        outbuf.assign(eng_.output());
        auto [wec, n] = co_await asio::async_write(
            sock_, asio::buffer(outbuf), asio::as_tuple(asio::use_awaitable));
        (void)n;
        (void)wec;
      }
    }
    pump_done_.hit();
    // If the writer died while the reader is parked, nudge the socket closed.
    asio::error_code ig;
    if constexpr (std::is_same_v<Stream, asio::ip::tcp::socket>) {
      sock_.close(ig);
    } else {
      sock_.lowest_layer().close(ig);
    }
  }

  // ---- state -----------------------------------------------------------------
  Stream sock_;
  App& app_;
  ShutdownRegistry& reg_;
  std::string prefeed_;
  bool tls_;
  std::string alpn_;
  std::string remote_ = "conn";
  H2Conn eng_;
  asio::experimental::channel<void(asio::error_code)> write_sig_;
  Latch pump_done_;
  std::map<std::uint32_t, std::shared_ptr<H2StreamRec>> streams_;
  std::vector<std::shared_ptr<H2StreamRec>> pending_cancel_;  // deferred emits
  std::size_t live_dispatched_ = 0;  // streams with a running handler (SSE etc.)
  int last_status_ = 0;
  std::chrono::steady_clock::time_point progress_deadline_{};
};

}  // namespace fw::h2

#endif  // FW_HTTP2
