// ===========================================================================
// examples/hello.cpp — a SECOND application built on the fw library.
//
// Deliberately chat-free: no chat_hub.hpp, no chat routes — just the
// framework. Proves the app/ ↔ fw/ boundary is real: the chat demo is one
// consumer of the library, this is another.
//
// Build (after `make` has built the objects):
//   g++ -std=c++26 -O2 -pthread -DFW_HTTP2=1 -DFW_TLS=1
//       -I"$ASIO_ROOT" -I.. -c examples/hello.cpp -o /tmp/hello.o
//   g++ -o /tmp/hello /tmp/hello.o fw/sessions.o
//       -pthread -lnghttp2 -lssl -lcrypto
//   /tmp/hello --port 18099 --docroot public
// ===========================================================================
#include "fw/fw.hpp"

using namespace fw;

asio::awaitable<void> page(HttpCtx& ctx, std::string greeting) {
  ctx.res = Response::html_page(200, "hello app",
                                "greeting: " + std::move(greeting));
  co_return;
}

int main(int argc, char** argv) {
  ServerConfig cfg;                       // defaults: 0.0.0.0:8080, ./public
  for (int i = 1; i + 1 < argc; ++i)      // minimal: just --port / --bind
    if (std::string_view(argv[i]) == "--port")
      cfg.port = unsigned(parse_num<int>(argv[i + 1]).value_or(8080));
    else if (std::string_view(argv[i]) == "--bind")
      cfg.bind_addr = argv[i + 1];

  App app;
  app.Get("/",    [](HttpCtx& c) -> asio::awaitable<void> { co_await page(c, "hello"); });
  app.Get("/hi/:name", [](HttpCtx& c) -> asio::awaitable<void> {
    co_await page(c, "hi " + c.req.params.at("name"));
  });

  // SSE: a ticking clock, driven through the same OutStream machinery.
  app.Get("/ticks", [](HttpCtx& c) -> asio::awaitable<void> {
    co_await c.begin_sse();
    for (int i = 0; i < 5 && !c.out->closed(); ++i) {
      c.sse("tick", json::Value(double(i)));
      asio::steady_timer t(co_await asio::this_coro::executor,
                           std::chrono::seconds(1));
      co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
    }
    c.out->finish();
  });

  ShutdownRegistry reg;
  asio::io_context ioc;
  Listener listener(ioc, app, cfg, reg);
  std::string err;
  if (!listener.start(err)) {
    std::fprintf(stderr, "startup failed: %s\n", err.c_str());
    return 1;
  }
  log(LogLevel::Info, "hello app listening on {}:{} (h2c works too)",
      cfg.bind_addr, cfg.port);
  asio::signal_set sig{ioc, SIGINT, SIGTERM};
  sig.async_wait([&](asio::error_code, int) {
    listener.stop();
    reg.shutdown_all();
    asio::steady_timer t{ioc, std::chrono::seconds(2)};
    t.async_wait([&](asio::error_code) { ioc.stop(); });
  });
  std::vector<std::thread> pool;
  for (unsigned i = 1; i < 4; ++i) pool.emplace_back([&ioc] { ioc.run(); });
  ioc.run();
  for (auto& t : pool) t.join();
  return 0;
}
