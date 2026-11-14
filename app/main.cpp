// ============================================================================
// app/main.cpp — CLI, bootstrap, signals, thread pool, main().
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#include "fw/fw.hpp"
#include "app/chat_hub.hpp"
#include "app/chat_routes.hpp"

namespace fw {

bool run_selftest();  // defined in selftest.cpp

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
void print_usage() {
  std::puts(
      "fw — C++26 asio web framework (HTTP/1.1 + HTTP/2 + SSE + chat demo)\n"
      "options:\n"
      "  --port N          TCP port (default 8080)\n"
      "  --bind ADDR       bind address (default 0.0.0.0)\n"
      "  --docroot DIR     static file root (default ./public)\n"
      "  --threads N       io threads (default: min(hw, 8))\n"
      "  --tls-cert FILE   TLS certificate chain (PEM)\n"
      "  --tls-key FILE    TLS private key (PEM)\n"
      "  --strict-tls      refuse plaintext HTTP on the TLS port\n"
      "                    (default: serve plaintext too — one port,\n"
      "                     TLS + h2c + HTTP/1.1 are auto-detected)\n"
      "  --no-h2c          refuse cleartext HTTP/2 prior-knowledge\n"
      "  --http1-only      disable HTTP/2 entirely\n"
      "  --max-upload N    upload size cap in bytes (default 52428800)\n"
      "  --max-body BYTES  request body limit (default 1048576)\n"
      "  --verbose         debug logging\n"
      "  --selftest        run unit tests and exit\n"
      "  --help            this help");
}

ServerConfig parse_args(int argc, char** argv) {
  ServerConfig cfg;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    auto next = [&]() -> std::string_view {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "missing value for %.*s\n", int(a.size()), a.data());
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "--port") cfg.port = unsigned(parse_num<int>(next()).value_or(8080));
    else if (a == "--bind") cfg.bind_addr = std::string(next());
    else if (a == "--docroot") cfg.docroot = std::string(next());
    else if (a == "--threads") cfg.threads = parse_num<int>(next()).value_or(0);
    else if (a == "--tls-cert") cfg.tls_cert = std::string(next());
    else if (a == "--tls-key") cfg.tls_key = std::string(next());
    else if (a == "--no-h2c") cfg.allow_h2c = false;
    else if (a == "--http1-only") cfg.http1_only = true;
    else if (a == "--strict-tls") cfg.strict_tls = true;
    else if (a == "--max-body")
      cfg.max_body_bytes = parse_num<std::size_t>(next()).value_or(1 << 20);
    else if (a == "--max-upload")
      cfg.max_upload_bytes = parse_num<std::size_t>(next()).value_or(
          50ull * 1024 * 1024);
    else if (a == "--verbose") cfg.verbose = true;
    else if (a == "--selftest") cfg.selftest = true;
    else if (a == "--help" || a == "-h") { print_usage(); std::exit(0); }
    else {
      std::fprintf(stderr, "unknown option %.*s\n", int(a.size()), a.data());
      std::exit(2);
    }
  }
  return cfg;
}


// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int run_main(int argc, char** argv) {
  ServerConfig cfg = parse_args(argc, argv);
  if (cfg.selftest) return run_selftest() ? 0 : 1;
  if (cfg.verbose) g_log_level.store(LogLevel::Debug);

  asio::io_context ioc;
  auto hub = std::make_shared<chat::ChatHub>(ioc.get_executor());
  hub->start();

  App app;
  app.limits = cfg.limits;
  app.limits.max_body_bytes = cfg.max_body_bytes;
  app.verbose_logging = cfg.verbose;
  std::error_code dec;
  if (std::filesystem::exists(cfg.docroot, dec))
    app.ServeStaticFrom(cfg.docroot);
  else
    log(LogLevel::Warn, "docroot '{}' not found — static serving disabled",
        cfg.docroot.string());
  chat::wire(app, *hub, cfg);

  ShutdownRegistry registry;
  Listener listener(ioc, app, cfg, registry);
  std::string err;
  if (!listener.start(err)) {
    log(LogLevel::Error, "startup failed: {}", err);
    return 1;
  }

#if FW_HTTP2
  const char* h2mode = cfg.http1_only ? "disabled (--http1-only)"
                      : (cfg.allow_h2c ? "enabled (TLS/ALPN + h2c prior-knowledge)"
                                       : "enabled (TLS/ALPN only)");
#else
  const char* h2mode = "not compiled in (build with FW_HTTP2=1)";
#endif
  const bool tls_on =
#if FW_TLS
      !cfg.tls_cert.empty() && !cfg.tls_key.empty();
#else
      false;
#endif
  const std::string scheme = tls_on ? "https" : "http";
  log(LogLevel::Info, "fw server listening on {}:{}  (chat UI: {}://localhost:{}/)",
      cfg.bind_addr, cfg.port, scheme, cfg.port);
  log(LogLevel::Info, "  HTTP/2 : {}", h2mode);
  if (tls_on) {
    log(LogLevel::Info, "  TLS    : {} / {} (plaintext on this port is "
                        "auto-detected and served too)", cfg.tls_cert,
        cfg.tls_key);
    if (!cfg.strict_tls)
      log(LogLevel::Info, "           use --strict-tls to refuse plaintext");
  }
  // Show every address the server is reachable on (esp. LAN IPs, for phones
  // / other machines) — getifaddrs is POSIX.
  {
    std::vector<std::string> urls;
#if defined(FW_HAS_GETIFADDRS)
    ifaddrs* ifs = nullptr;
    if (::getifaddrs(&ifs) == 0) {
      for (ifaddrs* i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr) continue;
        void* addr = nullptr;
        if (i->ifa_addr->sa_family == AF_INET)
          addr = &reinterpret_cast<sockaddr_in*>(i->ifa_addr)->sin_addr;
        else if (i->ifa_addr->sa_family == AF_INET6)
          addr = &reinterpret_cast<sockaddr_in6*>(i->ifa_addr)->sin6_addr;
        if (!addr) continue;
        char buf[INET6_ADDRSTRLEN] = {};
        if (!::inet_ntop(i->ifa_addr->sa_family, addr, buf, sizeof(buf)))
          continue;
        std::string ip = buf;
        if (ip.starts_with("fe80:") || ip == "::1") continue;  // link-local
        urls.push_back(std::format("{}://{}:{}/", scheme, ip, cfg.port));
      }
      ::freeifaddrs(ifs);
    }
#endif
    for (std::size_t i = 0; i < urls.size() && i < 6; ++i)
      log(LogLevel::Info, "  reach  : {}", urls[i]);
  }
  log(LogLevel::Info, "  try    : curl {}://localhost:{}/api/info", scheme,
      cfg.port);
  log(LogLevel::Info,
      "           curl --http2-prior-knowledge http://localhost:{}/api/info   # h2c",
      cfg.port);
  if (tls_on)
    log(LogLevel::Info,
        "           curl -k --http2 https://localhost:{}/api/info              # ALPN",
        cfg.port);
  log(LogLevel::Info, "           curl -N 'http://localhost:{}/health'", cfg.port);
  if (tls_on)
    log(LogLevel::Info,
        "  note   : the certificate is self-signed — browsers will warn; "
        "curl needs -k (or --cacert cert.pem if your cert covers the name)");

  asio::signal_set signals{ioc, SIGINT, SIGTERM};
  std::atomic<bool> stopping{false};
  signals.async_wait([&](asio::error_code, int sig) {
    if (stopping.exchange(true)) return;
    log(LogLevel::Info, "signal {} — graceful shutdown (5s deadline)", sig);
    asio::co_spawn(
        ioc.get_executor(),
        [&ioc, &listener, &registry]() -> asio::awaitable<void> {
          listener.stop();
          registry.shutdown_all();
          asio::steady_timer t{co_await asio::this_coro::executor,
                               std::chrono::seconds(5)};
          (void)co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
          ioc.stop();
        },
        asio::detached);
    // second signal → hard stop
    signals.async_wait([&](asio::error_code, int) { ioc.stop(); });
  });

  const unsigned n = cfg.threads > 0
                         ? static_cast<unsigned>(cfg.threads)
                         : std::clamp(std::thread::hardware_concurrency(), 1u, 8u);
  std::vector<std::thread> pool;
  pool.reserve(n - 1);
  for (unsigned i = 1; i < n; ++i) pool.emplace_back([&ioc] { ioc.run(); });
  ioc.run();
  for (auto& t : pool) t.join();
  log(LogLevel::Info, "stopped cleanly");
  return 0;
}

}  // namespace fw

int main(int argc, char** argv) { return fw::run_main(argc, argv); }
