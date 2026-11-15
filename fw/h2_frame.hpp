// ============================================================================
// fw/h2_frame.hpp — HTTP/2 wire framing (RFC 9113 §4): 9-byte frame header
// parse/build, per-frame payload parsers, constants. Pure, allocation-light,
// no asio — unit-testable in isolation.
// Part of the from-scratch HTTP/2 implementation (no nghttp2).
// ============================================================================
#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fw/detail/base.hpp"

namespace fw::h2::frame {

// ---- frame types (RFC 9113 §6) ---------------------------------------------
enum Type : std::uint8_t {
  kData = 0, kHeaders = 1, kPriority = 2, kRstStream = 3, kSettings = 4,
  kPushPromise = 5, kPing = 6, kGoaway = 7, kWindowUpdate = 8,
  kContinuation = 9,
};

// ---- flags -------------------------------------------------------------------
constexpr std::uint8_t kEndStream = 0x01;   // DATA, HEADERS
constexpr std::uint8_t kAck       = 0x01;   // SETTINGS, PING
constexpr std::uint8_t kEndHeaders = 0x04;  // HEADERS, CONTINUATION
constexpr std::uint8_t kPadded       = 0x08;   // DATA, HEADERS
constexpr std::uint8_t kPriorityFlag = 0x20;   // HEADERS (name: not the frame type)

// ---- error codes (RFC 9113 §7) ----------------------------------------------
enum Errc : std::uint32_t {
  kNoError = 0, kProtocolError = 1, kInternalError = 2, kFlowControlError = 3,
  kSettingsTimeout = 4, kStreamClosed = 5, kFrameSizeError = 6,
  kRefusedStream = 7, kCancel = 8, kCompressionError = 9, kConnectError = 10,
  kEnhanceYourCalm = 11, kInadequateSecurity = 12, kHttp11Required = 13,
};

// ---- settings ids (RFC 9113 §6.5.2) ------------------------------------------
enum Setting : std::uint16_t {
  kHeaderTableSize = 1, kEnablePush = 2, kMaxConcurrentStreams = 3,
  kInitialWindowSize = 4, kMaxFrameSize = 5, kMaxHeaderListSize = 6,
};

constexpr std::uint32_t kMaxFrameDefault = 16384;
constexpr std::uint32_t kMaxFrameAllowed = (1u << 24) - 1;  // spec cap 2^24-1
constexpr std::uint32_t kMaxWindow = 0x7fffffff;          // 2^31 - 1
constexpr std::uint32_t kInitialWindowDefault = 65535;
constexpr std::size_t kHeaderLen = 9;

// ---- frame header ------------------------------------------------------------
struct Header {
  std::uint32_t len = 0;      // payload length (24-bit)
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::uint32_t id = 0;       // 31-bit stream id (high bit stripped)
};

// Parse the fixed 9-byte header. `buf` must hold at least 9 bytes.
inline Header parse_header(const char* buf) {
  Header h;
  h.len = (std::uint32_t(std::uint8_t(buf[0])) << 16) |
          (std::uint32_t(std::uint8_t(buf[1])) << 8) |
          std::uint32_t(std::uint8_t(buf[2]));
  h.type = std::uint8_t(buf[3]);
  h.flags = std::uint8_t(buf[4]);
  h.id = (std::uint32_t(std::uint8_t(buf[5])) << 24) |
         (std::uint32_t(std::uint8_t(buf[6])) << 16) |
         (std::uint32_t(std::uint8_t(buf[7])) << 8) |
         std::uint32_t(std::uint8_t(buf[8]));
  h.id &= 0x7fffffff;
  return h;
}

// Header-only writer for callers that append the payload bytes themselves
// (append() below, and the control-frame emitters further down) — the
// length must be known up front.
inline void append_header(std::string& out, std::uint8_t type,
                          std::uint8_t flags, std::uint32_t id,
                          std::uint32_t payload_len) {
  out.push_back(char(std::uint8_t(payload_len >> 16)));
  out.push_back(char(std::uint8_t(payload_len >> 8)));
  out.push_back(char(std::uint8_t(payload_len)));
  out.push_back(char(type));
  out.push_back(char(flags));
  const std::uint32_t sid = id & 0x7fffffff;
  out.push_back(char(std::uint8_t(sid >> 24)));
  out.push_back(char(std::uint8_t(sid >> 16)));
  out.push_back(char(std::uint8_t(sid >> 8)));
  out.push_back(char(std::uint8_t(sid)));
}

// Append one complete frame (header + payload) to `out`.
inline void append(std::string& out, std::uint8_t type, std::uint8_t flags,
                   std::uint32_t id, std::string_view payload) {
  append_header(out, type, flags, id, std::uint32_t(payload.size()));
  out.append(payload);
}

inline void append_u32(std::string& s, std::uint32_t v) {
  s.push_back(char(std::uint8_t(v >> 24)));
  s.push_back(char(std::uint8_t(v >> 16)));
  s.push_back(char(std::uint8_t(v >> 8)));
  s.push_back(char(std::uint8_t(v)));
}

// Control frames with u32 (RST_STREAM, WINDOW_UPDATE) or u32+u32 (GOAWAY)
// bodies, written directly into `out` — no temporary payload string. These
// fire for every inbound DATA frame (WINDOW_UPDATE credit returns), so they
// are on the hot path of every h2 upload.
inline void append_u32_frame(std::string& out, std::uint8_t type,
                             std::uint8_t flags, std::uint32_t id,
                             std::uint32_t v) {
  out.reserve(out.size() + kHeaderLen + 4);
  append_header(out, type, flags, id, 4);
  append_u32(out, v);
}

inline void append_u32x2_frame(std::string& out, std::uint8_t type,
                               std::uint8_t flags, std::uint32_t id,
                               std::uint32_t a, std::uint32_t b) {
  out.reserve(out.size() + kHeaderLen + 8);
  append_header(out, type, flags, id, 8);
  append_u32(out, a);
  append_u32(out, b);
}

// ---- payload parsers (return false when malformed) ----------------------------

inline bool parse_settings(std::string_view p,
                           std::vector<std::pair<std::uint16_t, std::uint32_t>>& out) {
  if (p.size() % 6 != 0) return false;
  out.clear();
  for (std::size_t i = 0; i < p.size(); i += 6) {
    const std::uint16_t id = std::uint16_t(
        (std::uint8_t(p[i]) << 8) | std::uint8_t(p[i + 1]));
    const std::uint32_t val =
        (std::uint32_t(std::uint8_t(p[i + 2])) << 24) |
        (std::uint32_t(std::uint8_t(p[i + 3])) << 16) |
        (std::uint32_t(std::uint8_t(p[i + 4])) << 8) |
        std::uint32_t(std::uint8_t(p[i + 5]));
    out.emplace_back(id, val);
  }
  return true;
}

inline bool parse_u32_body(std::string_view p, std::uint32_t& out) {
  if (p.size() != 4) return false;
  out = (std::uint32_t(std::uint8_t(p[0])) << 24) |
        (std::uint32_t(std::uint8_t(p[1])) << 16) |
        (std::uint32_t(std::uint8_t(p[2])) << 8) |
        std::uint32_t(std::uint8_t(p[3]));
  return true;
}

inline bool parse_goaway(std::string_view p, std::uint32_t& last,
                        std::uint32_t& code, std::string_view& debug) {
  if (p.size() < 8) return false;
  last = (std::uint32_t(std::uint8_t(p[0])) << 24) |
         (std::uint32_t(std::uint8_t(p[1])) << 16) |
         (std::uint32_t(std::uint8_t(p[2])) << 8) |
         std::uint32_t(std::uint8_t(p[3]));
  last &= 0x7fffffff;
  code = (std::uint32_t(std::uint8_t(p[4])) << 24) |
         (std::uint32_t(std::uint8_t(p[5])) << 16) |
         (std::uint32_t(std::uint8_t(p[6])) << 8) |
         std::uint32_t(std::uint8_t(p[7]));
  debug = p.substr(8);
  return true;
}

inline bool parse_priority(std::string_view p, std::uint32_t& dep,
                           bool& exclusive, std::uint8_t& weight) {
  if (p.size() != 5) return false;
  dep = (std::uint32_t(std::uint8_t(p[0])) << 24) |
        (std::uint32_t(std::uint8_t(p[1])) << 16) |
        (std::uint32_t(std::uint8_t(p[2])) << 8) |
        std::uint32_t(std::uint8_t(p[3]));
  exclusive = (dep & 0x80000000u) != 0;
  dep &= 0x7fffffff;
  weight = std::uint8_t(p[4]);
  return true;
}

// Strip PADDED framing from a DATA/HEADERS payload. `p` is the whole payload
// (including the pad-length byte when the flag is set); `out` receives the
// unpadded view. Returns false when the padding fields are inconsistent.
inline bool strip_padding(std::string_view p, bool padded,
                          std::string_view& out) {
  if (!padded) {
    out = p;
    return true;
  }
  if (p.empty()) return false;
  const std::uint8_t pad = std::uint8_t(p[0]);
  if (std::size_t(pad) + 1 > p.size()) return false;
  out = p.substr(1, p.size() - 1 - pad);
  return true;
}

}  // namespace fw::h2::frame
