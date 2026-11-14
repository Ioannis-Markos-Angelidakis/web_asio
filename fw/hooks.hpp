// ============================================================================
// fw/hooks.hpp — ServerHooks (protocol sessions implement this) + HttpCtx + Handler/Middleware types. The seam that keeps handlers protocol-agnostic.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/message.hpp"
#include "fw/out_stream.hpp"
#include "fw/json.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// HttpCtx & protocol hooks
// ---------------------------------------------------------------------------
struct HttpCtx;

class ServerHooks {
 public:
  virtual ~ServerHooks() = default;
  // Whole-response write (plain responses). Honours HEAD.
  virtual asio::awaitable<void> send_response(HttpCtx& ctx) = 0;
  // Switch to streaming mode: writes status+headers, creates ctx.out and
  // spawns the single drain coroutine for this stream.
  virtual asio::awaitable<void> begin_stream(
      HttpCtx& ctx, int status, std::string content_type,
      std::vector<std::pair<std::string, std::string>> headers) = 0;
};

struct HttpCtx {
  Request req;
  Response res;
  ServerHooks* hooks = nullptr;   // protocol session (outlives the handler)
  std::shared_ptr<OutStream> out; // non-null after begin_stream()
  bool streaming = false;
  void* per_request = nullptr;    // protocol-private (h2 stream record)

  // SSE / streaming helpers
  asio::awaitable<void> begin_sse(
      std::vector<std::pair<std::string, std::string>> extra = {}) {
    std::vector<std::pair<std::string, std::string>> h = std::move(extra);
    h.emplace_back("cache-control", "no-cache");
    h.emplace_back("x-accel-buffering", "no");
    co_await hooks->begin_stream(*this, 200, "text/event-stream", std::move(h));
  }
  void sse(std::string_view event, const json::Value& data,
           std::string_view id = {}) {
    out->send(sse_event(event, json::serialize(data), id));
  }
};

using Handler    = std::function<asio::awaitable<void>(HttpCtx&)>;
using Middleware = std::function<asio::awaitable<void>(HttpCtx&, Handler)>;

}  // namespace fw
