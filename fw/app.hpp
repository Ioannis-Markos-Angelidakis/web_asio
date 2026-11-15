// ============================================================================
// fw/app.hpp — App — middleware pipeline, dispatch, docroot-jailed static file serving on a dedicated blocking-I/O pool.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"
#include "fw/limits.hpp"
#include "fw/config.hpp"
#include "fw/latch.hpp"
#include "fw/out_stream.hpp"
#include "fw/hooks.hpp"
#include "fw/router.hpp"
#include "fw/message.hpp"
#include "fw/json.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// App — routes, middleware, static files. Shared by both HTTP versions.
// ---------------------------------------------------------------------------
class App {
 public:
  Limits limits;
  bool verbose_logging = false;

  Router& router() { return router_; }
  void Get(std::string p, Handler h, std::size_t mb = 0)    { router_.add("GET", std::move(p), std::move(h), mb); }
  void Post(std::string p, Handler h, std::size_t mb = 0)   { router_.add("POST", std::move(p), std::move(h), mb); }
  void Put(std::string p, Handler h, std::size_t mb = 0)    { router_.add("PUT", std::move(p), std::move(h), mb); }
  void Delete(std::string p, Handler h, std::size_t mb = 0) { router_.add("DELETE", std::move(p), std::move(h), mb); }
  void Patch(std::string p, Handler h, std::size_t mb = 0)  { router_.add("PATCH", std::move(p), std::move(h), mb); }
  void Options(std::string p, Handler h, std::size_t mb = 0){ router_.add("OPTIONS", std::move(p), std::move(h), mb); }

  // Body-size limit for a (method, path) pair: the matched route's cap, or
  // the global default. Used BEFORE the body is read (h1) / while DATA
  // frames arrive (h2) so a 1 MiB default stays tight while /chat/upload
  // may accept large files.
  [[nodiscard]] std::size_t body_limit_for(std::string_view method,
                                           std::string_view path) const {
    Fields params;
    bool mismatch = false;
    if (const Router::Route* r = router_.match(method, path, params, mismatch))
      return r->max_body ? r->max_body : limits.max_body_bytes;
    return limits.max_body_bytes;
  }

  void Use(Middleware mw) { mws_.push_back(std::move(mw)); }

  void ServeStaticFrom(std::filesystem::path root) {
    docroot_ = std::move(root);
    std::error_code ec;
    docroot_canon_ = std::filesystem::weakly_canonical(*docroot_, ec);
    if (ec) docroot_canon_.clear();
  }

  // Serve one docroot-jailed file for an explicit relative path (used by
  // routes like GET / → sse.html, and /view-image, /download-file).
  asio::awaitable<void> serve_file(HttpCtx& ctx, std::string rel) {
    co_await serve_static_(ctx, std::move(rel));
  }

  // ---- blocking-work pool ------------------------------------------------------
  // Inherently blocking work (disk I/O for static files, and any blocking
  // call a user handler wants to make) runs here so io threads never stall.
  // The pool is sized at first use from the configuration (see main.cpp):
  //   App::configure_blocking_pool(n)   — before first use; 0/auto →
  //                                       auto_blocking_threads()
  //   App::blocking_pool()              — the pool (static lifetime: it
  //                                       outlives the io_context so late
  //                                       completions still drain at exit)
  // and handlers can offload with:
  //   co_await asio::co_spawn(App::blocking_pool().get_executor(),
  //                           []() -> asio::awaitable<T> {...},
  //                           asio::use_awaitable);
  inline static std::atomic<int> g_blocking_pool_threads{0};

  static void configure_blocking_pool(unsigned n) {
    g_blocking_pool_threads.store(int(n));  // must precede first blocking_pool()
  }

  static unsigned blocking_pool_size() {
    const int n = g_blocking_pool_threads.load(std::memory_order_relaxed);
    return n > 0 ? unsigned(n) : auto_blocking_threads();
  }

  static asio::thread_pool& blocking_pool() {
    static asio::thread_pool pool(blocking_pool_size());  // size frozen here
    return pool;
  }

  // Legacy alias (static file serving used to be its only customer).
  static asio::thread_pool& file_pool() { return blocking_pool(); }

  // Entry point used by both protocol sessions.
  asio::awaitable<void> dispatch(HttpCtx& ctx) {
    Handler run = [this](HttpCtx& c) -> asio::awaitable<void> {
      co_await route_or_static_(c);
    };
    for (auto it = mws_.rbegin(); it != mws_.rend(); ++it) {
      run = [mw = *it, next = std::move(run)](HttpCtx& c) mutable
            -> asio::awaitable<void> {
        co_await mw(c, next);
      };
    }
    co_await run(ctx);
  }

 private:
  asio::awaitable<void> route_or_static_(HttpCtx& ctx) {
    Request& req = ctx.req;
    if (req.method != "GET" && req.method != "POST" && req.method != "PUT" &&
        req.method != "DELETE" && req.method != "PATCH" && req.method != "HEAD" &&
        req.method != "OPTIONS") {
      ctx.res = Response::json_error(405, "method not allowed");
      ctx.res.status = 405;
      co_return;
    }
    bool mismatch = false;
    if (const Router::Route* r =
            router_.match(req.method, req.path, req.params, mismatch)) {
      co_await r->handler(ctx);
      co_return;
    }
    if (mismatch) {
      ctx.res = Response::json_error(405, "method not allowed for this path");
      co_return;
    }
    if (docroot_) {
      std::string rel = req.path;
      if (rel.starts_with('/')) rel.erase(0, 1);
      co_await serve_static_(ctx, std::move(rel));   // always fills res or streams
      co_return;
    }
    ctx.res = Response::html_page(404, "Not Found",
                                  "The path " + req.path + " does not exist.");
  }

  static bool is_within(const std::filesystem::path& p,
                        const std::filesystem::path& root) {
    auto pi = p.begin();
    auto ri = root.begin();
    for (; ri != root.end(); ++ri, ++pi) {
      if (pi == p.end() || *pi != *ri) return false;
    }
    return true;
  }

  asio::awaitable<void> serve_static_(HttpCtx& ctx, std::string rel) {
    namespace fs = std::filesystem;
    Request& req = ctx.req;
    if (req.method != "GET" && req.method != "HEAD") {
      ctx.res = Response::json_error(405, "static files are read-only");
      co_return;
    }
    // Refuse hidden path components (.git, .env, ...) and empty segments
    if (rel.empty() || rel.front() == '/') {
      ctx.res = Response::html_page(404, "Not Found", "No such file.");
      co_return;
    }
    for (std::size_t i = 0; i < rel.size();) {
      const std::size_t slash = rel.find('/', i);
      const std::size_t end = (slash == std::string::npos) ? rel.size() : slash;
      if (end > i && rel[i] == '.') {
        ctx.res = Response::html_page(404, "Not Found", "No such file.");
        co_return;
      }
      if (end == i) {  // "//" — refuse empty segments
        ctx.res = Response::html_page(404, "Not Found", "No such file.");
        co_return;
      }
      i = end + 1;
    }

    fs::path target = *docroot_ / fs::path(std::string_view(rel));
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(target, ec);
    if (ec || docroot_canon_.empty() || !is_within(canon, docroot_canon_)) {
      log(LogLevel::Debug, "static: refused {} (outside docroot)", req.path);
      ctx.res = Response::html_page(404, "Not Found", "No such file.");
      co_return;   // traversal attempt — answered as 404
    }
    if (fs::is_directory(canon)) {
      canon /= "index.html";
      if (!is_within(canon, docroot_canon_)) {
        ctx.res = Response::html_page(404, "Not Found", "No such file.");
        co_return;
      }
    }
    if (!fs::is_regular_file(canon)) {
      log(LogLevel::Debug, "static miss: {} (canon {})", req.path, canon.string());
      ctx.res = Response::html_page(404, "Not Found", "No such file.");
      co_return;
    }

    const std::uintmax_t size = fs::file_size(canon, ec);
    if (ec) {
      ctx.res = Response::json_error(500, "file error");
      co_return;
    }
    const std::string_view mime = mime_for(canon.string());

    // HEAD → headers only (content-length reflects the file size)
    if (req.method == "HEAD") {
      ctx.res.status = 200;
      ctx.res.content_type = std::string(mime);
      ctx.res.headers.emplace_back("content-length", std::to_string(size));
      co_return;
    }

    // Small file → single buffered response (read on the file pool, resume
    // on the connection strand afterwards).
    if (size <= limits.small_file_bytes) {
      std::string data = co_await read_file_async_(canon.string(),
                                                  static_cast<std::size_t>(size));
      if (data.empty() && size > 0) {
        ctx.res = Response::json_error(500, "cannot read file");
        co_return;
      }
      ctx.res.status = 200;
      ctx.res.content_type = std::string(mime);
      ctx.res.body = std::move(data);
      co_return;
    }

    // Large file → streamed through the bounded channel. A pool coroutine
    // performs blocking reads and awaits backpressured sends; the handler
    // waits for it so the session's finish() lands after all data (FIFO).
    ctx.res.status = 200;
    co_await ctx.hooks->begin_stream(ctx, 200, std::string(mime),
                                     {{"accept-ranges", "none"}});
    auto out = ctx.out;
    auto done = std::make_shared<Latch>(co_await asio::this_coro::executor);
    asio::co_spawn(file_pool().get_executor(),
                   [path = canon.string(), out, done]() -> asio::awaitable<void> {
      try {
        std::ifstream f(path, std::ios::binary);
        std::string buf(16 * 1024, '\0');  // 32-slot channel ≈ 512 KiB in flight
        while (f && !out->closed()) {
          f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
          const std::streamsize n = f.gcount();
          if (n <= 0) break;
          co_await out->send_await(
              std::string(buf.data(), static_cast<std::size_t>(n)));
        }
      } catch (...) {
        out->close();
      }
      done->hit();  // always release the waiter
    }, asio::detached);
    co_await done->wait();  // all chunks enqueued (or stream aborted)
  }

  // Runs a blocking file read on the file pool; the awaiting coroutine is
  // resumed on its original executor (strand).
  static asio::awaitable<std::string> read_file_async_(std::string path,
                                                      std::size_t max_bytes) {
    co_return co_await asio::co_spawn(
        file_pool().get_executor(),
        [path = std::move(path), max_bytes]() -> asio::awaitable<std::string> {
          std::string data;
          std::ifstream f(path, std::ios::binary);
          if (!f) co_return data;
          data.resize(max_bytes);
          f.read(data.data(), static_cast<std::streamsize>(data.size()));
          const std::streamsize n = f.gcount();
          data.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
          co_return data;
        },
        asio::use_awaitable);
  }

  Router router_;
  std::vector<Middleware> mws_;
  std::optional<std::filesystem::path> docroot_;
  std::filesystem::path docroot_canon_;
};
}  // namespace fw
