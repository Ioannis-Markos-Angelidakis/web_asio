// ============================================================================
// fw/util.hpp — Timeouts/clocks, logging, string & number helpers, percent decoding, random tokens, server identification.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// cancel_after compatibility alias (experimental in Asio 1.31 only)
// ---------------------------------------------------------------------------
#if __has_include(<asio/cancel_after.hpp>)
using ::asio::cancel_after;
#else
using ::asio::experimental::cancel_after;
#endif

inline constexpr auto kIoTimeout         = std::chrono::seconds{30};
inline constexpr auto kIdleKeepAlive    = std::chrono::seconds{75};
inline constexpr auto kH2IdleTimeout    = std::chrono::seconds{300};
inline constexpr auto kHandshakeTimeout = std::chrono::seconds{10};
// Whole-request deadline (h1) / no-complete-frame deadline (h2): bounds
// drip-feed (slowloris) attacks that keep per-read timeouts resetting.
inline constexpr auto kRequestDeadline   = std::chrono::seconds{30};

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
enum class LogLevel : int { Debug = 0, Info = 1, Warn = 2, Error = 3 };

inline std::atomic<LogLevel> g_log_level{LogLevel::Info};

inline const char* log_level_name(LogLevel lv) {
  switch (lv) {
    case LogLevel::Debug: return "debug";
    case LogLevel::Info:  return "info";
    case LogLevel::Warn:  return "warn";
    default:              return "error";
  }
}

// ---------------------------------------------------------------------------
// Calendar-time shims — POSIX spells these *_r(time, out); the Windows CRT
// spells them _s(out, time). MinGW-w64 provides both spellings, MSVC only
// the latter, so _WIN32 selects _s everywhere.
// ---------------------------------------------------------------------------
inline void fw_localtime(std::time_t t, std::tm& out) {
#if defined(_WIN32)
  ::localtime_s(&out, &t);
#else
  ::localtime_r(&t, &out);
#endif
}

inline void fw_gmtime(std::time_t t, std::tm& out) {
#if defined(_WIN32)
  ::gmtime_s(&out, &t);
#else
  ::gmtime_r(&t, &out);
#endif
}

template <class... Args>
void log(LogLevel lv, std::format_string<Args...> fmt, Args&&... args) {
  if (static_cast<int>(lv) < static_cast<int>(g_log_level.load(std::memory_order_relaxed)))
    return;
  const auto now = std::chrono::system_clock::now();
  const std::time_t tt = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  fw_localtime(tt, tm);
  char ts[16];
  std::strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
  std::fprintf(stderr, "%s [%-5s] %s\n", ts, log_level_name(lv),
               std::format(fmt, std::forward<Args>(args)...).c_str());
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------
inline std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// RFC 9110 HTTP-date (IMF-fixdate). The value changes once per second, so
// each thread caches the formatted string and refreshes it lazily — the
// per-response cost is one clock read and, 99.999% of the time, no
// allocation, no gmtime syscall, no strftime.
inline std::string_view http_date_now() {
  struct Dated {
    std::time_t t = -1;
    char buf[40] = {};
  };
  thread_local Dated d;
  const std::time_t tt = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  if (tt != d.t || d.t == -1) {
    d.t = tt;
    std::tm tm{};
    fw_gmtime(tt, tm);
    std::strftime(d.buf, sizeof(d.buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  }
  return {d.buf, std::strlen(d.buf)};
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------
inline char ascii_lower(char c) {
  return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
}

inline std::string to_lower_ascii(std::string_view in) {
  std::string out;
  out.resize(in.size());
  std::transform(in.begin(), in.end(), out.begin(),
                 [](unsigned char c) { return ascii_lower(char(c)); });
  return out;
}

// Lowercase-append into an existing buffer (no temporary string). Response
// serializers use this for every header they emit.
inline void append_lower_ascii(std::string& out, std::string_view in) {
  out.reserve(out.size() + in.size());
  for (char c : in) out.push_back(ascii_lower(c));
}

// Append with CR/LF/NUL stripped (header-injection defense) — the zero-copy
// form of sanitize_header_value().
inline void append_sanitized(std::string& out, std::string_view in) {
  out.reserve(out.size() + in.size());
  for (char c : in)
    if (c != '\r' && c != '\n' && c != '\0') out.push_back(c);
}

inline bool ieq_ascii(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i)
    if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
  return true;
}

inline std::string_view trim_ows(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

// tchar per RFC 9110 (token characters, incl. DIGIT / ALPHA)
inline bool is_tchar(char c) {
  unsigned char u = static_cast<unsigned char>(c);
  if (std::isdigit(u) || std::isalpha(u)) return true;
  static constexpr std::string_view extra = "!#$%&'*+-.^_`|~";
  return extra.find(c) != std::string_view::npos;
}

inline bool is_printable_text(std::string_view s) {
  for (unsigned char c : s)
    if (c < 0x20 || c == 0x7f) return false;
  return true;
}

// Defence-in-depth for response headers: strip CR/LF/NUL (header injection).
inline std::string sanitize_header_value(std::string_view v) {
  std::string out;
  out.reserve(v.size());
  for (char c : v)
    if (c != '\r' && c != '\n' && c != '\0') out.push_back(c);
  return out;
}

inline std::string html_escape(std::string_view in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (char c : in) {
    switch (c) {
      case '&':  out += "&amp;";  break;
      case '<':  out += "&lt;";   break;
      case '>':  out += "&gt;";   break;
      case '"':  out += "&quot;"; break;
      case '\'': out += "&#39;";  break;
      default:   out += c;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Percent decoding — rejects truncated escapes and NUL bytes.
// ---------------------------------------------------------------------------
inline std::expected<std::string, std::string> percent_decode(
    std::string_view in, bool plus_is_space) {
  auto hex_val = [](char h) -> int {
    if (h >= '0' && h <= '9') return h - '0';
    if (h >= 'a' && h <= 'f') return h - 'a' + 10;
    if (h >= 'A' && h <= 'F') return h - 'A' + 10;
    return -1;
  };
  std::string out;
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size(); ++i) {
    const char c = in[i];
    if (c == '%') {
      if (i + 2 >= in.size())
        return std::unexpected("truncated percent escape");
      const int hi = hex_val(in[i + 1]), lo = hex_val(in[i + 2]);
      if (hi < 0 || lo < 0)
        return std::unexpected("invalid percent escape");
      const char byte = static_cast<char>((hi << 4) | lo);
      if (byte == '\0')
        return std::unexpected("NUL byte in encoded data");
      out.push_back(byte);
      i += 2;
    } else if (plus_is_space && c == '+') {
      out.push_back(' ');
    } else {
      out.push_back(c);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Strict numeric conversion used for route params / query params / headers.
// ---------------------------------------------------------------------------
template <class T>
  requires std::integral<T> || std::floating_point<T>
std::expected<T, std::string> parse_num(std::string_view s) {
  T value{};
  const char* first = s.data();
  const char* last  = s.data() + s.size();
  auto [ptr, ec] = std::from_chars(first, last, value);
  if (ec != std::errc{} || ptr != last)
    return std::unexpected(std::format("invalid number '{}'", s));
  return value;
}

// ---------------------------------------------------------------------------
// Random tokens (session/chat tokens)
// ---------------------------------------------------------------------------
inline std::string random_token(std::size_t nbytes = 16) {
  static std::mutex mu;
  static std::mt19937_64 rng{std::random_device{}()};
  static std::uniform_int_distribution<unsigned> dist{0, 255};
  std::lock_guard<std::mutex> lk(mu);
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(nbytes * 2);
  for (std::size_t i = 0; i < nbytes; ++i) {
    const unsigned b = dist(rng);
    out.push_back(hex[b >> 4]);
    out.push_back(hex[b & 0xF]);
  }
  return out;
}


// ---------------------------------------------------------------------------
// Server identification
// ---------------------------------------------------------------------------
inline const std::string& server_id() {
  static const std::string id = [] {
#if FW_HTTP2
    return std::format("fw/3.0 (asio {}.{}.{} + pure-c++ http/2)",
                       ASIO_VERSION / 100000, (ASIO_VERSION / 100) % 1000,
                       ASIO_VERSION % 100);
#else
    return std::format("fw/3.0 (asio {}.{}.{})", ASIO_VERSION / 100000,
                       (ASIO_VERSION / 100) % 1000, ASIO_VERSION % 100);
#endif
  }();
  return id;
}

}  // namespace fw
