// ============================================================================
// app/chat_routes.cpp — Chat + upload route wiring (wire()).
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#include "fw/fw.hpp"
#include "app/chat_hub.hpp"

namespace fw {
namespace chat {
// ---------------------------------------------------------------------------
// Chat + upload routes
// ---------------------------------------------------------------------------
void wire(App& app, ChatHub& hub, const ServerConfig& cfg) {
  namespace fs = std::filesystem;

  app.Get("/health", [](HttpCtx& ctx) -> asio::awaitable<void> {
    ctx.res = Response::json(json::Value::obj({{"status", json::Value("ok")}}));
    co_return;
  });

  app.Get("/api/info", [threads = cfg.threads](HttpCtx& ctx) -> asio::awaitable<void> {
    json::Object o;
    o.emplace_back("name", json::Value("fw chat"));
    o.emplace_back("http_version", json::Value(double(ctx.req.http_version)));
    o.emplace_back("alpn", json::Value(ctx.req.alpn));
    o.emplace_back("tls", json::Value(ctx.req.tls));
    if (ctx.req.http_version == 2)
      o.emplace_back("stream_id", json::Value(double(ctx.req.h2_stream_id)));
    o.emplace_back("remote", json::Value(std::format(
        "{}:{}", ctx.req.remote_addr, ctx.req.remote_port)));
    o.emplace_back("server", json::Value(server_id()));
    o.emplace_back("threads", json::Value(double(threads)));
    ctx.res = Response::json(json::Value::obj(std::move(o)));
    co_return;
  });

  app.Get("/api/users", [&hub](HttpCtx& ctx) -> asio::awaitable<void> {
    ctx.res = Response::json(hub.users_json());
    co_return;
  });

  app.Get("/api/history", [&hub](HttpCtx& ctx) -> asio::awaitable<void> {
    std::size_t limit = 50;
    if (const std::string* ls = ctx.req.query_param("limit")) {
      auto n = parse_num<long long>(*ls);
      if (!n || *n < 1 || *n > 500) {
        ctx.res = Response::json_error(400, "limit must be 1..500");
        co_return;
      }
      limit = static_cast<std::size_t>(*n);
    }
    ctx.res = Response::json(hub.history_json(limit));
    co_return;
  });

  // ---- chat page: the original rich UI ------------------------------------
  app.Get("/", [&app](HttpCtx& ctx) -> asio::awaitable<void> {
    co_await app.serve_file(ctx, "sse.html");
  });

  // ---- SSE: join + stream ---------------------------------------------------
  app.Get("/chat-stream", [&hub](HttpCtx& ctx) -> asio::awaitable<void> {
    const std::string* username = ctx.req.query_param("username");
    if (!username) {
      ctx.res = Response::json_error(400, "missing ?username=");
      co_return;
    }
    auto token = hub.join(*username);  // atomic claim — proper 409 possible
    if (!token) {
      ctx.res = Response::json_error(token.error().status, token.error().msg);
      co_return;
    }
    co_await ctx.begin_sse();
    if (!hub.attach(*token, ctx.out)) {
      // impossible in practice (we hold the token), but stay defensive
      ctx.out->send(sse_event("error", json::serialize(json::Value::obj(
          {{"msg", json::Value("unknown token")}}))));
      ctx.out->finish();
      co_return;
    }
    struct Detach {
      ChatHub& h;
      std::shared_ptr<OutStream> o;
      ~Detach() { h.detach_stream(o); }
    } detach{hub, ctx.out};
    co_await ctx.out->wait_closed();  // returns only via close/abort/cancel
  });

  // ---- public + private messaging -------------------------------------------
  app.Post("/send", [&hub](HttpCtx& ctx) -> asio::awaitable<void> {
    auto body = json::parse(ctx.req.body);
    const json::Value* jtok = body ? body->find("token") : nullptr;
    const json::Value* jmsg = body ? body->find("message") : nullptr;
    if (!body || !jtok || !jtok->is_string() || !jmsg || !jmsg->is_string()) {
      ctx.res = Response::json_error(400, "need 'token' and 'message' strings");
      co_return;
    }
    auto id = hub.say(jtok->str(), jmsg->str());
    if (!id) ctx.res = Response::json_error(id.error().status, id.error().msg);
    else ctx.res = Response::json(json::Value::obj(
        {{"status", json::Value("sent")}, {"id", json::Value(*id)}}));
    co_return;
  });

  app.Post("/request-private-chat", [&hub](HttpCtx& ctx) -> asio::awaitable<void> {
    auto body = json::parse(ctx.req.body);
    const json::Value* jtok = body ? body->find("token") : nullptr;
    const json::Value* jto = body ? body->find("to") : nullptr;
    if (!body || !jtok || !jtok->is_string() || !jto || !jto->is_string()) {
      ctx.res = Response::json_error(400, "need 'token' and 'to' strings");
      co_return;
    }
    auto id = hub.request_private(jtok->str(), jto->str());
    if (!id) ctx.res = Response::json_error(id.error().status, id.error().msg);
    else ctx.res = Response::json(json::Value::obj(
        {{"status", json::Value("request_sent")}, {"request_id", json::Value(*id)}}));
    co_return;
  });

  app.Post("/respond-private-chat", [&hub](HttpCtx& ctx) -> asio::awaitable<void> {
    auto body = json::parse(ctx.req.body);
    const json::Value* jtok = body ? body->find("token") : nullptr;
    const json::Value* jrid = body ? body->find("request_id") : nullptr;
    const json::Value* jres = body ? body->find("response") : nullptr;
    if (!body || !jtok || !jtok->is_string() || !jrid || !jrid->is_string() ||
        !jres || !jres->is_string()) {
      ctx.res = Response::json_error(
          400, "need 'token', 'request_id', 'response' strings");
      co_return;
    }
    auto ok = hub.respond_private(jtok->str(), jrid->str(), jres->str());
    if (!ok) ctx.res = Response::json_error(ok.error().status, ok.error().msg);
    else ctx.res = Response::json(json::Value::obj(
        {{"status", json::Value("responded")}}));
    co_return;
  });

  app.Post("/send-private", [&hub](HttpCtx& ctx) -> asio::awaitable<void> {
    auto body = json::parse(ctx.req.body);
    const json::Value* jtok = body ? body->find("token") : nullptr;
    const json::Value* jto = body ? body->find("to") : nullptr;
    const json::Value* jmsg = body ? body->find("message") : nullptr;
    if (!body || !jtok || !jtok->is_string() || !jto || !jto->is_string() ||
        !jmsg || !jmsg->is_string()) {
      ctx.res = Response::json_error(400, "need 'token', 'to', 'message' strings");
      co_return;
    }
    auto id = hub.send_private(jtok->str(), jto->str(), jmsg->str());
    if (!id) ctx.res = Response::json_error(id.error().status, id.error().msg);
    else ctx.res = Response::json(json::Value::obj(
        {{"status", json::Value("sent")}, {"id", json::Value(*id)}}));
    co_return;
  });

  // ---- file upload (multipart) -----------------------------------------------
  app.Post("/chat/upload",
      [&hub, &cfg](HttpCtx& ctx) -> asio::awaitable<void> {
    const std::string* ct = ctx.req.header("content-type");
    auto boundary = ct ? multipart_boundary_of(*ct)
                        : std::unexpected(std::string("no content-type"));
    if (!boundary) {
      ctx.res = Response::json_error(400, "request must be multipart/form-data");
      co_return;
    }
    auto mp = multipart_parse(ctx.req.body, *boundary);
    if (!mp.success()) {
      ctx.res = Response::json_error(400, "multipart: " + mp.error);
      co_return;
    }
    const std::string token = mp.field("token");
    const MultipartFile* file = mp.file("file");
    if (token.empty()) {
      ctx.res = Response::json_error(401, "missing session token");
      co_return;
    }
    if (!file) {
      ctx.res = Response::json_error(400, "file data is missing");
      co_return;
    }
    if (file->empty()) {
      ctx.res = Response::json_error(400, "file cannot be empty");
      co_return;
    }
    if (file->size() > cfg.max_upload_bytes) {
      ctx.res = Response::json_error(400, std::format(
          "file is too large (max {} bytes)", cfg.max_upload_bytes));
      co_return;
    }
    auto who = hub.name_of(token);
    if (!who) {
      ctx.res = Response::json_error(401, "invalid session token");
      co_return;
    }

    const fs::path dir = cfg.docroot / "uploads";
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
      ctx.res = Response::json_error(500, "cannot create upload directory");
      co_return;
    }
    const std::string stored = std::format("{}_{}", now_ms(),
                                           sanitize_upload_filename(file->filename));
    const fs::path dest = dir / stored;
    {
      // Blocking write on the dedicated file pool (never on an io thread).
      auto written = co_await asio::co_spawn(
          App::file_pool().get_executor(),
          [dest, data = std::string_view(file->data)]()
              -> asio::awaitable<bool> {
            std::ofstream f(dest, std::ios::binary | std::ios::trunc);
            if (!f) co_return false;
            f.write(data.data(), static_cast<std::streamsize>(data.size()));
            co_return f.good();
          },
          asio::use_awaitable);
      if (!written) {
        ctx.res = Response::json_error(500, "failed to save file on server");
        co_return;
      }
    }
    // Extension — never the client MIME — decides inline rendering.
    const std::string ext =
        to_lower_ascii(fs::path(stored).extension().string());
    const bool is_image = is_inline_image_extension(ext);
    const std::string url = "/uploads/" + stored;
    auto ok = hub.broadcast_file(token, file->filename, url, is_image);
    if (!ok) {
      ctx.res = Response::json_error(ok.error().status, ok.error().msg);
      co_return;
    }
    ctx.res = Response::json(json::Value::obj(
        {{"status", json::Value("uploaded")}, {"url", json::Value(url)}}));
    co_return;
  },
      cfg.max_upload_bytes + 256 * 1024);  // route body cap (file + framing)

  // ---- safe image viewing / download ------------------------------------------
  app.Get("/view-image/:name", [&app, &cfg](HttpCtx& ctx) -> asio::awaitable<void> {
    const std::string* name = ctx.req.raw_param("name");
    if (!name || !safe_storage_name(*name)) {
      ctx.res = Response::json_error(403, "access denied");
      co_return;
    }
    const std::string ext = to_lower_ascii(
        std::filesystem::path(*name).extension().string());
    const bool svg = (ext == ".svg");
    if (!is_inline_image_extension(ext) && !svg) {
      ctx.res = Response::json_error(403, "this endpoint only serves images");
      co_return;
    }
    const fs::path path = cfg.docroot / "uploads" / *name;
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
      ctx.res = Response::json_error(404, "file not found");
      co_return;
    }
    co_await app.serve_file(ctx, "uploads/" + *name);
    ctx.res.headers.emplace_back("x-content-type-options", "nosniff");
    if (svg) {
      // SVG can carry script and inline event handlers: sandbox + download.
      ctx.res.headers.emplace_back("content-security-policy", "sandbox");
      ctx.res.headers.emplace_back("content-disposition",
                                   "attachment; filename=\"" +
                                       sanitize_header_value(*name) + "\"");
    }
    co_return;
  });

  app.Get("/download-file/:name", [&app, &cfg](HttpCtx& ctx) -> asio::awaitable<void> {
    const std::string* name = ctx.req.raw_param("name");
    if (!name || !safe_storage_name(*name)) {
      ctx.res = Response::json_error(403, "access denied");
      co_return;
    }
    const fs::path path = cfg.docroot / "uploads" / *name;
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
      ctx.res = Response::json_error(404, "file not found");
      co_return;
    }
    // Friendlier download name: strip the "<timestamp>_" prefix.
    std::string original = *name;
    if (const auto us = original.find('_'); us != std::string::npos)
      original = original.substr(us + 1);
    co_await app.serve_file(ctx, "uploads/" + *name);
    ctx.res.headers.emplace_back("x-content-type-options", "nosniff");
    ctx.res.headers.emplace_back(
        "content-disposition",
        "attachment; filename=\"" + sanitize_header_value(original) + "\"");
    co_return;
  });
}

}  // namespace chat
}  // namespace fw
