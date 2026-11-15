// ============================================================================
// fw/message.hpp — HTTP status text, MIME mapping, SSE framing, Request and Response value types, target parsing (shared by h1 and h2).
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"
#include "fw/json.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// HTTP status text + MIME mapping + SSE framing
// ---------------------------------------------------------------------------
inline std::string_view http_status_text(int status) {
  switch (status) {
    case 100: return "Continue";
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 416: return "Range Not Satisfiable";
    case 417: return "Expectation Failed";
    case 421: return "Misdirected Request";
    case 422: return "Unprocessable Content";
    case 426: return "Upgrade Required";
    case 428: return "Precondition Required";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 451: return "Unavailable For Legal Reasons";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 505: return "HTTP Version Not Supported";
    default:  return "Status";
  }
}

inline std::string_view mime_for(std::string_view path) {
  const auto dot = path.rfind('.');
  std::string_view ext;
  if (dot != std::string_view::npos) ext = path.substr(dot + 1);
  // Linear scan over a fixed table with an in-place case-insensitive
  // compare: zero allocation, one cache-friendly pass — the old version
  // lower-cased the extension into a heap string for a map lookup on every
  // static response.
  static constexpr std::pair<std::string_view, std::string_view> kMime[] = {
      {"html", "text/html; charset=utf-8"},
      {"htm",  "text/html; charset=utf-8"},
      {"css",  "text/css; charset=utf-8"},
      {"js",   "text/javascript; charset=utf-8"},
      {"mjs",  "text/javascript; charset=utf-8"},
      {"json", "application/json; charset=utf-8"},
      {"txt",  "text/plain; charset=utf-8"},
      {"md",   "text/markdown; charset=utf-8"},
      {"xml",  "application/xml; charset=utf-8"},
      {"png",  "image/png"},
      {"jpg",  "image/jpeg"},
      {"jpeg", "image/jpeg"},
      {"gif",  "image/gif"},
      {"svg",  "image/svg+xml"},
      {"webp", "image/webp"},
      {"avif", "image/avif"},
      {"ico",  "image/x-icon"},
      {"pdf",  "application/pdf"},
      {"wasm", "application/wasm"},
      {"woff", "font/woff"},
      {"woff2","font/woff2"},
      {"mp4",  "video/mp4"},
      {"webm", "video/webm"},
      {"mp3",  "audio/mpeg"},
      {"zip",  "application/zip"},
  };
  if (ext.size() <= 5) {  // longest entry is 4 — skip the scan otherwise
    for (const auto& [e, m] : kMime) {
      if (e.size() == ext.size() && ieq_ascii(e, ext)) return m;
    }
  }
  return "application/octet-stream";
}

// Format exactly ONE SSE frame. Single serialization point (this used to be
// a double-serialization bug in the old code). Handles multi-line payloads.
inline std::string sse_event(std::string_view event, std::string_view data,
                             std::string_view id = {}) {
  std::string out;
  out.reserve(data.size() + event.size() + 32);
  if (!id.empty()) { out += "id: ";  out += id;  out += '\n'; }
  if (!event.empty()) { out += "event: "; out += event; out += '\n'; }
  std::size_t start = 0;
  for (;;) {
    const std::size_t nl = data.find('\n', start);
    out += "data: ";
    out += data.substr(start, nl == std::string_view::npos
                                  ? std::string_view::npos
                                  : nl - start);
    out += '\n';
    if (nl == std::string_view::npos) break;
    start = nl + 1;
  }
  out += '\n';
  return out;
}


// ---------------------------------------------------------------------------
// Request / Response
// ---------------------------------------------------------------------------
// Flat, ordered name/value storage for request metadata. Header lists are
// small (≤ Limits::max_headers) and dominated by pointer chasing — a
// contiguous vector of SSO strings beats std::map on allocation count (one
// buffer instead of a red-black node + rebalancing per entry) and cache
// behavior, and preserves insertion order. set_* keeps the old map
// semantics: first position wins, value replaced ("last write wins").
using Fields = std::vector<std::pair<std::string, std::string>>;

inline const std::string* field_get(const Fields& f, std::string_view name) {
  for (const auto& [k, v] : f)
    if (k == name) return &v;
  return nullptr;
}

// Insert or overwrite (same observable behavior as `map[key] = value`).
inline void field_set(Fields& f, std::string name, std::string value) {
  for (auto& [k, v] : f) {
    if (k == name) {
      v = std::move(value);
      return;
    }
  }
  f.emplace_back(std::move(name), std::move(value));
}

struct Request {
  int http_version = 1;                 // 1 or 2
  std::string method;                   // "GET", "POST", ...
  std::string target;                   // raw request target as received
  std::string path;                     // percent-decoded path
  std::string raw_query;                // raw query string (no '?')
  Fields headers;                       // lower-cased names, insertion order
  Fields query;                         // decoded, insertion order
  Fields params;                        // route params, insertion order
  std::string body;
  std::string remote_addr;
  unsigned short remote_port = 0;
  bool tls = false;
  std::string alpn;                     // "h2" / "http/1.1" / ""
  std::int64_t h2_stream_id = 0;        // HTTP/2 only
  bool keep_alive = true;

  const std::string* header(std::string_view name) const {
    return field_get(headers, name);
  }
  const std::string* query_param(std::string_view name) const {
    return field_get(query, name);
  }
  const std::string* raw_param(std::string_view name) const {
    return field_get(params, name);
  }
  void set_header(std::string name, std::string value) {
    field_set(headers, std::move(name), std::move(value));
  }
  void set_query(std::string name, std::string value) {
    field_set(query, std::move(name), std::move(value));
  }
  void set_param(std::string name, std::string value) {
    field_set(params, std::move(name), std::move(value));
  }
  // Typed route-parameter access (":id<uint32>") — std::expected based.
  template <class T>
    requires std::integral<T> || std::floating_point<T>
  std::expected<T, std::string> param(std::string_view name) const {
    const std::string* s = raw_param(name);
    if (!s) return std::unexpected(std::format("missing param '{}'", name));
    return parse_num<T>(*s);
  }
};

struct Response {
  int status = 200;
  std::string content_type = "text/plain; charset=utf-8";
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;

  static Response text(std::string b, int st = 200) {
    Response r;
    r.status = st;
    r.content_type = "text/plain; charset=utf-8";
    r.body = std::move(b);
    return r;
  }
  static Response html(std::string b, int st = 200) {
    Response r;
    r.status = st;
    r.content_type = "text/html; charset=utf-8";
    r.body = std::move(b);
    return r;
  }
  static Response json(const json::Value& v, int st = 200) {
    Response r;
    r.status = st;
    r.content_type = "application/json; charset=utf-8";
    r.body = json::serialize(v);
    return r;
  }
  static Response json_error(int st, std::string_view msg) {
    return json(json::Value::obj({{"error", json::Value(std::string(msg))}}), st);
  }
  static Response html_page(int st, std::string_view title, std::string_view body_html) {
    std::string b = std::format(
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>{}</title><style>"
        "body{{font-family:system-ui,sans-serif;background:#111318;color:#e6e8ee;"
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}"
        ".card{{background:#1a1e27;border:1px solid #2a3040;border-radius:12px;"
        "padding:2rem 3rem;text-align:center}}h1{{margin:0 0 .5rem;font-size:2.5rem}}"
        "p{{color:#9aa3b5;margin:0}}"
        "</style></head><body><div class=\"card\"><h1>{}</h1><p>{}</p>"
        "<p>{}</p></div>"
        "</body></html>",
        html_escape(title), std::to_string(st), html_escape(title),
        html_escape(body_html));
    return html(std::move(b), st);
  }
};


// Parse target into path/query (shared by both protocol parsers).
// Returns an HTTP status + message on failure.
inline std::optional<std::pair<int, std::string>> init_request_target(
    Request& req) {
  std::string_view t = req.target;
  if (t.starts_with("http://") || t.starts_with("https://")) {
    const auto scheme = t.find("://");
    const auto slash = t.find('/', scheme + 3);
    t = (slash == std::string_view::npos) ? std::string_view("/") : t.substr(slash);
  }
  if (t.empty() || t[0] != '/')
    return std::make_pair(400, std::string("invalid request target"));
  const auto q = t.find('?');
  std::string_view pathv = t.substr(0, q);
  std::string_view query = (q == std::string_view::npos) ? std::string_view{}
                                                         : t.substr(q + 1);
  if (pathv.size() > 8192)
    return std::make_pair(414, std::string("request target too long"));
  auto dec = percent_decode(pathv, /*plus_is_space=*/false);
  if (!dec)
    return std::make_pair(400, "bad percent-encoding: " + dec.error());
  req.path = std::move(*dec);
  req.raw_query = std::string(query);
  // Query params (decode failures per-key are skipped)
  std::size_t i = 0;
  while (i < query.size()) {
    const auto amp = query.find('&', i);
    const std::size_t end = (amp == std::string_view::npos) ? query.size() : amp;
    if (end > i) {
      const auto eq = query.find('=', i);
      std::string_view kv = query.substr(i, (eq == std::string_view::npos ? end : eq) - i);
      std::string_view vv = (eq == std::string_view::npos || eq >= end)
                                ? std::string_view{}
                                : query.substr(eq + 1, end - eq - 1);
      auto k = percent_decode(kv, true);
      auto v = percent_decode(vv, true);
      if (k && v) req.set_query(std::move(*k), std::move(*v));
    }
    if (amp == std::string_view::npos) break;
    i = amp + 1;
  }
  return std::nullopt;
}

}  // namespace fw
