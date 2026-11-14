// ============================================================================
// app/chat_hub.hpp — ChatHub — shared chat state: atomic username claim + token (two-phase join), history, private chats, flood control.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"
#include "fw/json.hpp"
#include "fw/message.hpp"
#include "fw/out_stream.hpp"

namespace fw {
// ===========================================================================
// Chat hub — the ORIGINAL feature set of the demo, hardened:
//   * username-claim join + server-issued token (atomic, TOCTOU-free)
//   * welcome / history / message / user_connected / user_connected events
//   * private-chat request → accept/decline handshake with unique ids
//   * private_message + private_chat_ended on the same SSE connection
//   * file_message broadcast (uploads saved by the route, see wire())
//   * flood control, 15 s SSE keepalive
// All methods are thread-safe (single mutex, no I/O under the lock; delivery
// is via OutStream::send() which posts onto the connection strand).
// ===========================================================================
namespace chat {

// ---- upload filename hygiene -----------------------------------------------
inline bool safe_storage_name(std::string_view name) {
  if (name.empty() || name.size() > 100 || name.front() == '.')
    return false;
  for (const char c : name)
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' &&
        c != '_' && c != '-')
      return false;
  return true;
}

// Sanitize an untrusted original filename before it touches the disk.
inline std::string sanitize_upload_filename(std::string_view in) {
  std::string out;
  out.reserve(in.size());
  for (const char c : in)
    out += (std::isalnum(static_cast<unsigned char>(c)) || c == '.' ||
            c == '_' || c == '-')
               ? c
               : '_';
  const auto first = out.find_first_not_of('.');
  out = (first == std::string::npos) ? std::string("file")
                                     : out.substr(first);
  if (out.size() > 100) out.resize(100);
  return out;
}

// The extension decides whether a file may render inline — NEVER the
// client-supplied MIME type.
inline bool is_inline_image_extension(std::string_view ext_with_dot) {
  return ext_with_dot == ".png" || ext_with_dot == ".jpg" ||
         ext_with_dot == ".jpeg" || ext_with_dot == ".gif" ||
         ext_with_dot == ".webp";
}

class ChatHub : public std::enable_shared_from_this<ChatHub> {
 public:
  struct Err { int status; std::string msg; };

  explicit ChatHub(asio::any_io_executor ex, std::size_t history_cap = 200)
      : ex_(std::move(ex)), hist_cap_(history_cap) {}

  // 15-second SSE keepalive / liveness heartbeat.
  void start() {
    asio::co_spawn(ex_, [self = shared_from_this()]() -> asio::awaitable<void> {
      asio::steady_timer t(self->ex_);
      for (;;) {
        t.expires_after(std::chrono::seconds(15));
        auto [ec] = co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
        (void)ec;
        std::lock_guard<std::mutex> lk(self->m_);
        for (auto& [name, u] : self->users_)
          if (u.out && !u.out->closed()) u.out->send(": keepalive\n\n");
      }
    }, asio::detached);
  }

  // Step 1 of joining: atomically claim the username, issue a token. The
  // user is "online" the moment this returns (no co_await in between, so
  // two concurrent joins can never both win). The SSE stream attaches in a
  // second step — that split is what lets the HTTP layer answer 409 with a
  // proper status line before any SSE headers were written.
  std::expected<std::string, Err> join(std::string_view name) {
    if (name.empty() || name.size() > 32 || !is_printable_text(name))
      return std::unexpected(Err{400, "username must be 1-32 printable characters"});
    std::lock_guard<std::mutex> lk(m_);
    auto it = users_.find(std::string(name));
    if (it != users_.end()) {
      if (it->second.out && !it->second.out->closed())
        return std::unexpected(Err{409, "username already taken"});
      remove_user_locked_(it);  // stale ghost (SSE died moments ago) — evict
    }
    User u;
    u.name = std::string(name);
    u.token = random_token(16);
    const std::string token = u.token;
    users_.emplace(u.name, std::move(u));
    by_token_[token] = std::string(name);
    log(LogLevel::Info, "chat: '{}' joined", name);
    return token;
  }

  // Step 2: bind the SSE stream to a joined user; sends welcome + history,
  // announces the user to everyone else.
  bool attach(std::string_view token, const std::shared_ptr<OutStream>& out) {
    std::lock_guard<std::mutex> lk(m_);
    const auto uit = users_.find(token_name_locked_(token));
    if (uit == users_.end()) return false;
    User& u = uit->second;
    if (u.out && u.out != out) u.out->close();  // one SSE stream per user
    u.out = out;

    json::Array users;
    for (const auto& [n, us] : users_) users.emplace_back(json::Value(n));
    deliver_locked_(u, "welcome", json::Value::obj({
        {"type", json::Value("welcome")},
        {"user", json::Value(u.name)},
        {"token", json::Value(u.token)},
        {"users", json::Value::arr(std::move(users))},
        {"message", json::Value("Welcome, " + u.name + "! You are connected.")},
    }));
    if (!history_.empty())
      deliver_locked_(u, "history",
                      json::Value::obj({{"type", json::Value("history")},
                                        {"messages", history_json_locked_(20)}}));
    broadcast_user_event_locked_(u.name, "user_connected", u.out.get());
    return true;
  }

  void detach_stream(const std::shared_ptr<OutStream>& out) {
    if (!out) return;
    std::lock_guard<std::mutex> lk(m_);
    for (auto it = users_.begin(); it != users_.end(); ++it) {
      if (it->second.out == out) {
        remove_user_locked_(it);
        return;
      }
    }
  }

  // Display name for a token (auth helper for the POST routes).
  std::optional<std::string> name_of(std::string_view token) {
    std::lock_guard<std::mutex> lk(m_);
    const std::string* n = token_name_ptr_locked_(token);
    if (!n) return std::nullopt;
    return std::optional<std::string>(*n);
  }

  std::expected<std::string, Err> say(std::string_view token,
                                      std::string_view text) {
    if (text.empty() || text.size() > 4000)
      return std::unexpected(Err{400, "message must be 1-4000 characters"});
    std::lock_guard<std::mutex> lk(m_);
    User* u = by_token_user_locked_(token);
    if (!u) return std::unexpected(Err{401, "invalid session token — please reconnect"});
    if (!rate_ok_locked_(*u)) return std::unexpected(Err{429, "too many messages"});
    const std::string id = next_id_locked_("m");
    const double ts = now_ms() / 1000.0;
    json::Object o;
    o.emplace_back("type", json::Value("message"));
    o.emplace_back("user", json::Value(u->name));
    o.emplace_back("message", json::Value(std::string(text)));
    o.emplace_back("timestamp", json::Value(ts));
    o.emplace_back("id", json::Value(id));
    history_.push_back(o);
    if (history_.size() > hist_cap_) history_.pop_front();
    broadcast_locked_(nullptr, "", json::Value(std::move(o)));  // unnamed event
    return id;
  }

  std::expected<std::string, Err> request_private(std::string_view token,
                                                  std::string_view to) {
    std::lock_guard<std::mutex> lk(m_);
    User* from = by_token_user_locked_(token);
    if (!from) return std::unexpected(Err{401, "invalid session token"});
    const auto tit = users_.find(std::string(to));
    if (tit == users_.end())
      return std::unexpected(Err{404, "user not found (they may have left)"});
    if (tit->second.name == from->name)
      return std::unexpected(Err{400, "cannot start a private chat with yourself"});
    // Unique per request: nobody can guess (or collide with) another
    // conversation's stream, and two chats between the same pair get
    // separate streams.
    const std::string request_id = random_token(6);
    from->pending_request = request_id;
    from->pending_request_to = tit->second.name;
    deliver_locked_(tit->second, "private_chat_request", json::Value::obj({
        {"type", json::Value("private_chat_request")},
        {"from", json::Value(from->name)},
        {"to", json::Value(tit->second.name)},
        {"request_id", json::Value(request_id)},
        {"message", json::Value(from->name + " wants to start a private chat with you")},
    }));
    return request_id;
  }

  std::expected<std::monostate, Err> respond_private(std::string_view token,
                                                     std::string_view request_id,
                                                     std::string_view response) {
    if (response != "accept" && response != "decline")
      return std::unexpected(Err{400, "response must be 'accept' or 'decline'"});
    std::lock_guard<std::mutex> lk(m_);
    User* responder = by_token_user_locked_(token);
    if (!responder) return std::unexpected(Err{401, "invalid session token"});
    // Only the user the request was addressed to may answer it.
    User* requester = nullptr;
    for (auto& [n, u] : users_) {
      (void)n;
      if (u.pending_request == request_id &&
          u.pending_request_to == responder->name) {
        requester = &u;
        break;
      }
    }
    if (!requester)
      return std::unexpected(Err{404, "request not found or expired"});
    requester->pending_request.clear();
    requester->pending_request_to.clear();

    if (response == "decline") {
      const json::Value ev = json::Value::obj({
          {"type", json::Value("private_chat_declined")},
          {"from", json::Value(requester->name)},
          {"to", json::Value(responder->name)},
          {"message", json::Value(responder->name + " declined the private chat request")},
      });
      if (requester->out && !requester->out->closed())
        requester->out->send(sse_event("private_chat_declined",
                                       json::serialize(ev)));
      if (responder->out && !responder->out->closed())
        responder->out->send(sse_event("private_chat_declined",
                                       json::serialize(ev)));
      return std::monostate{};
    }

    // accept: create the (unique) private chat and start it for both.
    const std::string chat_name = "private_" + std::string(request_id);
    PrivateChat pc;
    pc.a = requester->name;
    pc.b = responder->name;
    private_chats_[chat_name] = pc;
    requester->private_chat = chat_name;
    responder->private_chat = chat_name;
    const json::Value ev = json::Value::obj({
        {"type", json::Value("private_chat_started")},
        {"from", json::Value(requester->name)},
        {"to", json::Value(responder->name)},
        {"participants", json::Value::arr(
             {json::Value(requester->name), json::Value(responder->name)})},
        {"stream_name", json::Value(chat_name)},
        {"message", json::Value("Private chat started")},
    });
    const std::string frame = sse_event("private_chat_started",
                                        json::serialize(ev));
    if (requester->out && !requester->out->closed())
      requester->out->send(frame);
    if (responder->out && !responder->out->closed())
      responder->out->send(frame);
    log(LogLevel::Info, "chat: private chat '{}' ↔ '{}' started",
        requester->name, responder->name);
    return std::monostate{};
  }

  std::expected<std::string, Err> send_private(std::string_view token,
                                               std::string_view to,
                                               std::string_view text) {
    if (text.empty() || text.size() > 4000)
      return std::unexpected(Err{400, "message must be 1-4000 characters"});
    std::lock_guard<std::mutex> lk(m_);
    User* from = by_token_user_locked_(token);
    if (!from) return std::unexpected(Err{401, "invalid session token"});
    if (from->private_chat.empty())
      return std::unexpected(Err{404, "you are not in a private chat"});
    const auto cit = private_chats_.find(from->private_chat);
    if (cit == private_chats_.end()) {
      from->private_chat.clear();
      return std::unexpected(Err{404, "private chat no longer exists"});
    }
    const PrivateChat& pc = cit->second;
    const std::string other = (pc.a == from->name) ? pc.b : pc.a;
    if (to != other)
      return std::unexpected(Err{404, "recipient is not in this private chat"});
    if (!rate_ok_locked_(*from))
      return std::unexpected(Err{429, "too many messages"});
    const std::string id = next_id_locked_("prv");
    const json::Value ev = json::Value::obj({
        {"type", json::Value("private_message")},
        {"from", json::Value(from->name)},
        {"to", json::Value(other)},
        {"message", json::Value(std::string(text))},
        {"stream", json::Value(from->private_chat)},
        {"id", json::Value(id)},
    });
    const std::string frame =
        sse_event("private_message", json::serialize(ev));
    if (from->out && !from->out->closed()) from->out->send(frame);
    const auto tit = users_.find(other);
    if (tit != users_.end() && tit->second.out && !tit->second.out->closed())
      tit->second.out->send(frame);
    return id;
  }

  // Called by the upload route after the file is safely on disk.
  std::expected<std::monostate, Err> broadcast_file(std::string_view token,
                                                    std::string_view original_name,
                                                    std::string_view url,
                                                    bool is_image) {
    std::lock_guard<std::mutex> lk(m_);
    User* u = by_token_user_locked_(token);
    if (!u) return std::unexpected(Err{401, "invalid session token"});
    broadcast_locked_(nullptr, "", json::Value::obj({
        {"type", json::Value("file_message")},
        {"user", json::Value(u->name)},
        {"original_name", json::Value(std::string(original_name))},
        {"url", json::Value(std::string(url))},
        {"file_type", json::Value(is_image ? "image" : "file")},
    }));
    return std::monostate{};
  }

  json::Value users_json() {
    std::lock_guard<std::mutex> lk(m_);
    json::Array a;
    for (const auto& [n, u] : users_) a.emplace_back(json::Value(n));
    return json::Value::arr(std::move(a));
  }

  json::Value history_json(std::size_t limit) {
    std::lock_guard<std::mutex> lk(m_);
    return history_json_locked_(limit);
  }

 private:
  struct User {
    std::string name, token;
    std::shared_ptr<OutStream> out;   // SSE stream of this user
    std::string pending_request;      // request_id this user sent (awaiting)
    std::string pending_request_to;   // whom it was sent to
    std::string private_chat;         // active private chat ("" = none)
    std::deque<std::chrono::steady_clock::time_point> rate;
  };
  struct PrivateChat {
    std::string a, b;  // participant names
  };

  const std::string* token_name_ptr_locked_(std::string_view token) {
    const auto it = by_token_.find(std::string(token));
    if (it == by_token_.end()) return nullptr;
    return &it->second;
  }
  std::string token_name_locked_(std::string_view token) {
    const std::string* n = token_name_ptr_locked_(token);
    return n ? *n : std::string();
  }
  User* by_token_user_locked_(std::string_view token) {
    const std::string* n = token_name_ptr_locked_(token);
    if (!n) return nullptr;
    const auto it = users_.find(*n);
    return it == users_.end() ? nullptr : &it->second;
  }

  bool rate_ok_locked_(User& u) {
    const auto now = std::chrono::steady_clock::now();
    u.rate.push_back(now);
    while (!u.rate.empty() && now - u.rate.front() > std::chrono::seconds(10))
      u.rate.pop_front();
    return u.rate.size() <= 30;
  }

  std::string next_id_locked_(std::string_view prefix) {
    return std::format("{}-{}-{}", prefix, ++id_seq_, random_token(2));
  }

  void deliver_locked_(const User& u, std::string_view event,
                       const json::Value& data) {
    if (u.out && !u.out->closed())
      u.out->send(sse_event(event, json::serialize(data)));
  }

  // Named event to everyone (skip == nullptr) — used by private_* events.
  void broadcast_locked_(const OutStream* skip, std::string_view event,
                         const json::Value& data) {
    const std::string frame = sse_event(event, json::serialize(data));
    for (auto& [n, u] : users_) {
      (void)n;
      if (u.out.get() == skip) continue;
      if (u.out && !u.out->closed()) u.out->send(frame);
    }
  }

  // user_connected / user_disconnected are unnamed events (the client's
  // onmessage handler dispatches on data.type).
  void broadcast_user_event_locked_(const std::string& name,
                                    std::string_view type,
                                    const OutStream* skip) {
    broadcast_locked_(skip, "", json::Value::obj({
        {"type", json::Value(std::string(type))},
        {"user", json::Value(name)},
    }));
  }

  void remove_user_locked_(std::map<std::string, User>::iterator it) {
    User u = std::move(it->second);
    users_.erase(it);
    by_token_.erase(u.token);
    // End any private chat this user was in: the partner is notified once.
    if (!u.private_chat.empty()) {
      const auto cit = private_chats_.find(u.private_chat);
      if (cit != private_chats_.end()) {
        const std::string other =
            (cit->second.a == u.name) ? cit->second.b : cit->second.a;
        private_chats_.erase(cit);
        const auto pit = users_.find(other);
        if (pit != users_.end()) {
          pit->second.private_chat.clear();
          deliver_locked_(pit->second, "private_chat_ended",
                          json::Value::obj({
                              {"type", json::Value("private_chat_ended")},
                              {"user", json::Value(u.name)},
                              {"message",
                               json::Value(u.name + " left the private chat")},
                          }));
        }
      }
    }
    if (u.out) {
      u.out->send(sse_event(
          "bye", json::serialize(json::Value::obj(
                     {{"user", json::Value(u.name)}}))));
      u.out->finish();  // graceful end of the SSE stream
    }
    broadcast_user_event_locked_(u.name, "user_disconnected", nullptr);
    log(LogLevel::Info, "chat: '{}' left", u.name);
  }

  json::Value history_json_locked_(std::size_t limit) {
    json::Array a;
    const std::size_t n = std::min(limit, history_.size());
    for (std::size_t i = history_.size() - n; i < history_.size(); ++i)
      a.emplace_back(json::Value(history_[i]));
    return json::Value::arr(std::move(a));
  }

  asio::any_io_executor ex_;
  std::mutex m_;
  std::map<std::string, User> users_;
  std::map<std::string, std::string> by_token_;
  std::map<std::string, PrivateChat> private_chats_;
  std::deque<json::Object> history_;
  std::size_t hist_cap_;
  std::uint64_t id_seq_ = 0;
};

}  // namespace chat
}  // namespace fw
