// ============================================================================
// fw/h2_conn.hpp — HTTP/2 connection engine (RFC 9113), written from scratch
// on top of fw/h2_frame.hpp + fw/h2_hpack.hpp. Pure, asio-free state machine
// so it can be unit-tested headless:
//
//   feed(bytes)  → protocol events (on_* callbacks, exactly one direction)
//   submit_*()   → queue responses / data / RST / GOAWAY
//   produce()    → serialize everything currently sendable into `output()`
//                  (DATA frames honor per-stream + connection flow windows)
//
// Concurrency: the owning session runs everything on one strand; the engine
// itself does no locking. Invariant mirrored from the previous design: the
// engine never spawns anything — events fire synchronously from feed() or
// produce(), and the session defers cancellation work accordingly.
// ============================================================================
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fw/detail/base.hpp"
#include "fw/h2_frame.hpp"
#include "fw/h2_hpack.hpp"
#include "fw/h2_hpack_tables.hpp"

namespace fw::h2 {

// What the engine needs from the server's Limits.
struct H2EngineLimits {
  std::uint32_t max_concurrent_streams = 100;
  std::size_t max_header_count = 100;
  std::size_t max_header_bytes = 32 * 1024;
  std::uint32_t recv_initial_window = 1u << 20;  // we advertise (per stream)
  std::uint32_t recv_conn_window = 1u << 20;     // we bump the conn window to
  std::uint32_t max_frame_size = 16384;          // inbound cap (we advertise)
};

// Protocol events the owning session implements. All callbacks are sync and
// must not call back into the engine (the session defers its cancel work).
class H2ConnEvents {
 public:
  virtual ~H2ConnEvents() = default;
  // A HEADERS block starts on a fresh client stream. Return false to refuse
  // (engine answers RST REFUSED_STREAM; the block is still HPACK-decoded to
  // keep the shared compression state consistent, entries dropped).
  virtual bool on_begin_request(std::uint32_t id) = 0;
  virtual void on_header(std::uint32_t id, std::string_view name,
                         std::string_view value) = 0;
  // Header block complete (CONTINUATIONs joined). `end_stream` mirrors the
  // HEADERS frame's flag; `trailers` marks a trailing header section.
  virtual void on_headers_end(std::uint32_t id, bool end_stream,
                              bool trailers) = 0;
  // DATA payload (padding stripped). Return false after RSTing the stream
  // (limits); the engine stops delivering and returns only credit.
  virtual bool on_data(std::uint32_t id, std::string_view payload) = 0;
  virtual void on_end_stream(std::uint32_t id) = 0;  // dispatch point
  // Stream went away: RST received/sent, refused, response END_STREAM, …
  virtual void on_stream_close(std::uint32_t id, std::uint32_t errc) = 0;
  virtual void on_goaway() = 0;
  virtual void on_sendq_empty(std::uint32_t id) = 0;  // low-water → wake drain
  virtual void on_progress() = 0;  // any complete inbound frame (liveness)
};

class H2Conn {
 public:
  H2Conn(H2EngineLimits lim, H2ConnEvents& ev)  // limits BY VALUE (a
      : lim_(lim), ev_(ev), dec_(4096) {}  // reference would dangle on
                                                // temporaries at call sites)

  // ---- inbound ---------------------------------------------------------
  bool feed(const char* data, std::size_t n);
  bool alive() const { return !fatal_; }
  bool goaway_received() const { return goaway_recv_; }

  // ---- outbound (queued; serialized by produce()) ----------------------
  void start();  // our SETTINGS + connection WINDOW_UPDATE bump

  void submit_response(
      std::uint32_t id,
      const std::vector<std::pair<std::string_view, std::string_view>>& headers,
      bool end_stream);

  void submit_data(std::uint32_t id, std::string chunk, bool end_after);
  void submit_rst(std::uint32_t id, std::uint32_t code);
  void submit_goaway(std::uint32_t code);  // graceful: last stream seen

  std::size_t queued_bytes(std::uint32_t id) const;
  bool stream_exists(std::uint32_t id) const;

  // ---- output -----------------------------------------------------------
  bool want_write() const;
  void produce();
  std::string_view output() const { return out_; }
  void consume(std::size_t n) { out_.erase(0, n); }

 private:
  struct Stream {
    std::int64_t send_window = 65535;  // our sending window (client controls)
    std::deque<std::string> sendq;
    std::size_t queued = 0;
    bool finish_after = false;   // END_STREAM once the queue drains
    bool refused = false;        // refused stream: decode, drop, RST
    bool remote_closed = false;  // client sent END_STREAM
    bool closed = false;         // done (RST / final frame sent)
    bool got_first_headers = false;
    bool sendq_empty_fired = true;
  };

  Stream* find_(std::uint32_t id) {
    const auto it = streams_.find(id);
    return it == streams_.end() ? nullptr : &it->second;
  }
  bool fail_(std::uint32_t code);  // emit GOAWAY, mark dead
  void rst_close_(std::uint32_t id, std::uint32_t code);
  void close_sent_(std::uint32_t id, std::uint32_t code);  // erase + event
  void process_frame_(const frame::Header& hd, std::string_view payload);
  bool finish_header_block_();  // returns false on fatal error
  std::size_t open_stream_count_() const {
    std::size_t n = 0;
    for (const auto& [sid, s] : streams_)
      if (!s.closed && !s.refused) ++n;
    return n;
  }
  void emit_window_update_(std::uint32_t id, std::uint32_t inc) {
    std::string p;
    frame::append_u32(p, inc);
    frame::append(out_, frame::kWindowUpdate, 0, id, p);
  }
  void emit_settings_ack_() {
    frame::append(out_, frame::kSettings, frame::kAck, 0, {});
  }
  void emit_ping_ack_(std::string_view payload) {
    frame::append(out_, frame::kPing, frame::kAck, 0, payload);
  }

  H2EngineLimits lim_;
  H2ConnEvents& ev_;  // the owning session (callbacks fire on the strand)
  hpack::Decoder dec_;
  hpack::Encoder enc_;

  // inbound buffer (feed may split frames arbitrarily)
  std::string rbuf_;
  std::size_t rpos_ = 0;

  // preface + first-SETTINGS handshake state
  std::size_t preface_matched_ = 0;
  bool got_first_settings_ = false;

  // header-block assembly (HEADERS + CONTINUATION)
  bool in_headers_ = false;
  std::uint32_t headers_id_ = 0;
  std::uint8_t headers_flags_ = 0;
  std::string fragment_;

  std::map<std::uint32_t, Stream> streams_;
  std::uint32_t last_client_id_ = 0;
  std::int64_t conn_send_window_ = 65535;

  // peer (client) settings that affect what we may send
  std::uint32_t peer_max_frame_ = 16384;
  std::uint32_t peer_initial_window_ = 65535;

  bool fatal_ = false;
  bool goaway_recv_ = false;

  std::string out_;
};

// ---------------------------------------------------------------------------
inline bool H2Conn::fail_(std::uint32_t code) {
  if (fatal_) return true;
  fatal_ = true;
  std::string p;
  frame::append_u32(p, last_client_id_ & 0x7fffffff);
  frame::append_u32(p, code);
  frame::append(out_, frame::kGoaway, 0, 0, p);
  return true;
}

inline void H2Conn::rst_close_(std::uint32_t id, std::uint32_t code) {
  if (fatal_) return;
  std::string p;
  frame::append_u32(p, code);
  frame::append(out_, frame::kRstStream, 0, id, p);
  close_sent_(id, code);
}

inline void H2Conn::close_sent_(std::uint32_t id, std::uint32_t code) {
  if (const auto it = streams_.find(id); it != streams_.end()) {
    it->second.closed = true;
    it->second.sendq.clear();
    it->second.queued = 0;
    it->second.finish_after = false;
  }
  ev_.on_stream_close(id, code);
  streams_.erase(id);
}

// ---------------------------------------------------------------------------
inline void H2Conn::start() {
  std::string p;
  auto put = [&](std::uint16_t id, std::uint32_t v) {
    p.push_back(char(std::uint8_t(id >> 8)));
    p.push_back(char(std::uint8_t(id)));
    frame::append_u32(p, v);
  };
  put(frame::kMaxConcurrentStreams, lim_.max_concurrent_streams);
  put(frame::kInitialWindowSize, lim_.recv_initial_window);
  put(frame::kMaxHeaderListSize, std::uint32_t(lim_.max_header_bytes));
  frame::append(out_, frame::kSettings, 0, 0, p);
  if (lim_.recv_conn_window > frame::kInitialWindowDefault)
    emit_window_update_(0,
                        lim_.recv_conn_window - frame::kInitialWindowDefault);
}

inline bool H2Conn::feed(const char* data, std::size_t n) {
  if (fatal_) return false;
  rbuf_.append(data, n);
  while (true) {
    std::size_t avail = rbuf_.size() - rpos_;

    // client preface (exactly once, at the very start)
    if (preface_matched_ < kPreface.size()) {
      const std::size_t want = kPreface.size() - preface_matched_;
      const std::size_t have = std::min(want, avail);
      if (kPreface.substr(preface_matched_, have) !=
          std::string_view(rbuf_).substr(rpos_, have)) {
        fail_(frame::kProtocolError);
        return false;
      }
      preface_matched_ += have;
      rpos_ += have;
      avail -= have;
      if (preface_matched_ < kPreface.size()) break;  // need more bytes
    }

    if (avail < frame::kHeaderLen) break;
    const frame::Header hd = frame::parse_header(rbuf_.data() + rpos_);
    if (hd.len > lim_.max_frame_size) {
      fail_(frame::kFrameSizeError);
      return false;
    }
    if (avail < frame::kHeaderLen + std::size_t(hd.len)) break;
    const std::string_view payload =
        std::string_view(rbuf_).substr(rpos_ + frame::kHeaderLen, hd.len);
    rpos_ += frame::kHeaderLen + std::size_t(hd.len);

    if (in_headers_ && hd.type != frame::kContinuation) {
      fail_(frame::kProtocolError);  // HEADERS must be contiguous
      return false;
    }
    if (!got_first_settings_ && hd.type != frame::kSettings) {
      fail_(frame::kProtocolError);  // first frame must be SETTINGS
      return false;
    }
    process_frame_(hd, payload);
    if (fatal_) return false;
    ev_.on_progress();

    if (rpos_ == rbuf_.size()) {
      rbuf_.clear();
      rpos_ = 0;
    } else if (rpos_ > (1u << 16)) {
      rbuf_.erase(0, rpos_);
      rpos_ = 0;
    }
  }
  if (rpos_ > (1u << 16)) {
    rbuf_.erase(0, rpos_);
    rpos_ = 0;
  }
  return true;
}

inline void H2Conn::process_frame_(const frame::Header& hd,
                                   std::string_view payload) {
  using namespace frame;
  switch (hd.type) {
    case kSettings: {
      if (hd.id != 0) { fail_(kProtocolError); return; }
      if (hd.flags & kAck) {
        if (!payload.empty()) fail_(kFrameSizeError);
        return;  // ack of our SETTINGS
      }
      std::vector<std::pair<std::uint16_t, std::uint32_t>> iv;
      if (!parse_settings(payload, iv)) { fail_(kFrameSizeError); return; }
      for (const auto& [id, v] : iv) {
        switch (id) {
          case kInitialWindowSize: {
            if (v > kMaxWindow) { fail_(kFlowControlError); return; }
            const std::int64_t delta =
                std::int64_t(v) - std::int64_t(peer_initial_window_);
            for (auto& [sid, st] : streams_) {
              (void)sid;
              if (st.closed) continue;
              st.send_window += delta;
              if (st.send_window < 0 || st.send_window > kMaxWindow) {
                fail_(kFlowControlError);
                return;
              }
            }
            peer_initial_window_ = v;
            break;
          }
          case kMaxFrameSize:
            if (v < kMaxFrameDefault || v > kMaxFrameAllowed) {
              fail_(kProtocolError);
              return;
            }
            peer_max_frame_ = v;
            break;
          default:
            break;  // table size / push / concurrency / unknown: not needed
        }
      }
      got_first_settings_ = true;
      emit_settings_ack_();
      return;
    }
    case kPing: {
      if (hd.id != 0 || payload.size() != 8) { fail_(kFrameSizeError); return; }
      if ((hd.flags & kAck) == 0) emit_ping_ack_(payload);
      return;
    }
    case kWindowUpdate: {
      std::uint32_t inc = 0;
      if (!parse_u32_body(payload, inc)) { fail_(kFrameSizeError); return; }
      if (inc == 0) {  // §6.9: zero increment is a protocol error
        if (hd.id == 0) fail_(kProtocolError);
        else rst_close_(hd.id, kProtocolError);
        return;
      }
      if (hd.id == 0) {
        conn_send_window_ += std::int64_t(inc);
        if (conn_send_window_ > kMaxWindow) { fail_(kFlowControlError); return; }
      } else if (Stream* st = find_(hd.id); st && !st->closed) {
        st->send_window += std::int64_t(inc);
        if (st->send_window > kMaxWindow) {
          rst_close_(hd.id, kFlowControlError);
          return;
        }
      }
      return;
    }
    case kHeaders: {
      if (hd.id == 0 || (hd.id & 1) == 0) { fail_(kProtocolError); return; }
      Stream* existing = find_(hd.id);
      if (existing && (existing->remote_closed || existing->closed)) {
        fail_(kProtocolError);  // no HEADERS after END_STREAM / on dead id
        return;
      }
      if (!existing) {
        if (hd.id <= last_client_id_) {
          fail_(kProtocolError);  // client ids must be monotonically new
          return;
        }
        last_client_id_ = hd.id;
      }
      // payload layout: [pad-len] [priority(5)] fragment [padding]
      std::string_view frag = payload;
      if (hd.flags & kPadded) {
        if (!strip_padding(payload, true, frag)) { fail_(kProtocolError); return; }
      } else {
        frag = payload;
      }
      if (hd.flags & kPriorityFlag) {  // parse-and-discard (deprecated §5.3)
        if (frag.size() < 5) { fail_(kFrameSizeError); return; }
        std::uint32_t dep = 0;
        bool excl = false;
        std::uint8_t w = 0;
        (void)parse_priority(frag.substr(0, 5), dep, excl, w);
        if (dep == hd.id) { fail_(kProtocolError); return; }  // self-dep
        frag.remove_prefix(5);
      }
      in_headers_ = true;
      headers_id_ = hd.id;
      headers_flags_ = hd.flags;
      fragment_.assign(frag);
      if (hd.flags & kEndHeaders) {
        if (!finish_header_block_()) return;  // fatal already emitted
      }
      return;
    }
    case kContinuation: {
      if (!in_headers_ || hd.id != headers_id_) { fail_(kProtocolError); return; }
      fragment_.append(payload);
      if (hd.flags & kEndHeaders) {
        if (!finish_header_block_()) return;
      }
      return;
    }
    case kData: {
      if (hd.id == 0) { fail_(kProtocolError); return; }
      std::string_view body = payload;
      if (hd.flags & kPadded) {
        if (!strip_padding(payload, true, body)) { fail_(kProtocolError); return; }
      }
      Stream* st = find_(hd.id);
      const bool deliverable =
          st && !st->closed && !st->refused && !st->remote_closed;
      if (!deliverable) {
        // stream gone/closed: return connection credit so the peer survives
        if (!body.empty()) emit_window_update_(0, std::uint32_t(body.size()));
        return;
      }
      const bool consumed = body.empty() || ev_.on_data(hd.id, body);
      if (consumed && !body.empty()) {  // replenish → uploads keep streaming
        emit_window_update_(hd.id, std::uint32_t(body.size()));
        emit_window_update_(0, std::uint32_t(body.size()));
      }
      if (hd.flags & kEndStream) {
        st->remote_closed = true;
        ev_.on_end_stream(hd.id);
      }
      return;
    }
    case kRstStream: {
      std::uint32_t code = 0;
      if (!parse_u32_body(payload, code) || hd.id == 0) {
        fail_(kFrameSizeError);
        return;
      }
      if (streams_.count(hd.id)) close_sent_(hd.id, code);
      return;  // unknown/idle: leniently ignored
    }
    case kPriority: {
      if (payload.size() != 5) { fail_(kFrameSizeError); return; }
      return;  // advisory; deprecated — validate & drop
    }
    case kPushPromise:  // a client MUST NOT push
      fail_(kProtocolError);
      return;
    case kGoaway: {
      std::uint32_t last = 0, code = 0;
      std::string_view dbg;
      if (!parse_goaway(payload, last, code, dbg)) { fail_(kFrameSizeError); return; }
      goaway_recv_ = true;
      ev_.on_goaway();
      return;
    }
    default:
      return;  // unknown frame types MUST be ignored
  }
}

inline bool H2Conn::finish_header_block_() {
  using namespace frame;
  in_headers_ = false;
  const std::uint32_t id = headers_id_;
  const bool end_stream = (headers_flags_ & kEndStream) != 0;
  const std::string block = std::move(fragment_);
  fragment_.clear();

  Stream* st = find_(id);
  const bool first_block = !st || !st->got_first_headers;

  // Decide acceptance before decoding (decode MUST happen regardless, to
  // keep HPACK dynamic-table state in lockstep with the peer).
  if (!st) {
    const auto [it, ok] = streams_.emplace(id, Stream{});
    (void)ok;
    st = &it->second;
    st->send_window = std::int64_t(peer_initial_window_);
    const bool refuse = open_stream_count_() > lim_.max_concurrent_streams;
    if (refuse || !ev_.on_begin_request(id)) {
      // NB: rst_close_() erases the stream — `st` is invalid afterwards.
      st->refused = true;
      rst_close_(id, kRefusedStream);
      st = nullptr;
    }
  }
  if (st) st->got_first_headers = true;

  std::vector<std::pair<std::string, std::string>> headers;
  const std::string err = dec_.decode(block, lim_.max_header_count,
                                      lim_.max_header_bytes, headers);
  if (err == "compression") {
    fail_(kCompressionError);  // HPACK errors are connection errors
    return false;
  }
  if (err == "too_large") {  // header bomb → refuse the stream, stay alive
    if (st && !st->closed) rst_close_(id, kEnhanceYourCalm);
    return true;
  }
  if (!st) return true;  // decoded for state; content discarded (refused)

  const bool trailers = !first_block;
  if (!trailers) {
    for (const auto& [n, v] : headers) ev_.on_header(id, n, v);
  }
  ev_.on_headers_end(id, end_stream, trailers);
  if (end_stream) {
    if (Stream* s2 = find_(id)) {
      s2->remote_closed = true;
      ev_.on_end_stream(id);
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
inline void H2Conn::submit_response(
    std::uint32_t id,
    const std::vector<std::pair<std::string_view, std::string_view>>& headers,
    bool end_stream) {
  if (fatal_) return;
  Stream* st = find_(id);
  if (!st || st->closed || st->refused) return;  // gone — caller learns via events

  std::string block;
  for (const auto& [n, v] : headers) enc_.encode(n, v, block);

  // HEADERS (+ CONTINUATION if the block exceeds the peer's max frame size)
  std::size_t off = 0;
  bool first = true;
  do {
    const std::size_t take =
        std::min(block.size() - off, std::size_t(peer_max_frame_));
    const std::string_view frag(block.data() + off, take);
    off += take;
    const bool last = (off == block.size());
    std::uint8_t flags = last ? frame::kEndHeaders : std::uint8_t(0);
    if (first && end_stream) flags |= frame::kEndStream;
    frame::append(out_, first ? frame::kHeaders : frame::kContinuation, flags,
                  id, frag);
    first = false;
  } while (off < block.size());

  if (end_stream) close_sent_(id, frame::kNoError);
}

inline void H2Conn::submit_data(std::uint32_t id, std::string chunk,
                                bool end_after) {
  if (fatal_) return;
  Stream* st = find_(id);
  if (!st || st->closed || st->refused) return;
  if (!chunk.empty()) {
    st->queued += chunk.size();
    st->sendq.push_back(std::move(chunk));
    st->sendq_empty_fired = false;
  }
  if (end_after) st->finish_after = true;
}

inline void H2Conn::submit_rst(std::uint32_t id, std::uint32_t code) {
  if (fatal_) return;
  if (streams_.count(id)) rst_close_(id, code);
}

inline void H2Conn::submit_goaway(std::uint32_t code) {
  if (fatal_) return;
  std::string p;
  frame::append_u32(p, last_client_id_ & 0x7fffffff);
  frame::append_u32(p, code);
  frame::append(out_, frame::kGoaway, 0, 0, p);
}

inline std::size_t H2Conn::queued_bytes(std::uint32_t id) const {
  const auto it = streams_.find(id);
  return it == streams_.end() ? 0 : it->second.queued;
}

inline bool H2Conn::stream_exists(std::uint32_t id) const {
  return streams_.count(id) != 0;
}

inline bool H2Conn::want_write() const {
  if (!out_.empty()) return true;
  if (fatal_) return false;
  for (const auto& [id, st] : streams_) {
    (void)id;
    if (st.closed || st.refused) continue;
    if (st.queued > 0 || st.finish_after) return true;
  }
  return false;
}

// Serialize DATA (control frames were appended eagerly at submit time),
// honoring per-stream + connection flow windows. One frame per stream per
// round → no stream starves its neighbors.
inline void H2Conn::produce() {
  for (;;) {
    bool progress = false;
    std::vector<std::uint32_t> finished;
    for (auto& [id, st] : streams_) {
      if (st.closed || st.refused) continue;

      if (st.queued == 0) {
        if (st.finish_after) {  // END_STREAM-only DATA frame
          frame::append(out_, frame::kData, frame::kEndStream, id, {});
          finished.push_back(id);
          progress = true;
        } else if (!st.sendq_empty_fired) {
          st.sendq_empty_fired = true;
          ev_.on_sendq_empty(id);  // low-water → session wakes its drain
        }
        continue;
      }
      if (conn_send_window_ <= 0 || st.send_window <= 0) continue;  // deferred

      // NB: cap by the FRONT chunk's size, not the queue total — `chunk`
      // below is a view into exactly that one string. (Sending a partial
      // front chunk is fine: the next round continues where we stopped.)
      const std::size_t n = std::min<std::size_t>(
          {std::size_t(peer_max_frame_), std::size_t(st.send_window),
           std::size_t(conn_send_window_), st.sendq.front().size()});
      const std::string_view chunk(st.sendq.front().data(), n);
      const bool end = (n == st.queued) && st.finish_after;
      frame::append(out_, frame::kData, end ? frame::kEndStream : std::uint8_t(0),
                    id, chunk);
      st.sendq.front().erase(0, n);
      if (st.sendq.front().empty()) st.sendq.pop_front();
      st.queued -= n;
      st.send_window -= std::int64_t(n);
      conn_send_window_ -= std::int64_t(n);
      progress = true;
      if (end) finished.push_back(id);
    }
    for (const std::uint32_t id : finished) close_sent_(id, frame::kNoError);
    if (!progress) break;
  }
}

}  // namespace fw::h2
