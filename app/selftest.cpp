// ============================================================================
// app/selftest.cpp — Unit self-tests (run with --selftest).
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#include "fw/fw.hpp"
#include "fw/detail/mem_probe.hpp"
#include "app/chat_hub.hpp"

#include <cstdlib>
#if defined(_WIN32)
#include <malloc.h>  // _aligned_malloc / _aligned_free
#endif

// ============================================================================
// Global allocation probe (fw/detail/mem_probe.hpp): counting new/delete
// for the whole webfw binary. Inert unless a MemProbe is active — then each
// allocation costs one relaxed atomic increment. Frees are not counted (the
// regressions below measure allocation counts, not leak checks — leaks are
// the sanitizer builds' job).
// ============================================================================
namespace {

void probe_count(std::size_t n) {
  if (fw::detail::g_mem_probe_active.load(std::memory_order_relaxed)) {
    fw::detail::g_mem_probe_allocs.fetch_add(1, std::memory_order_relaxed);
    fw::detail::g_mem_probe_bytes.fetch_add(std::int64_t(n),
                                            std::memory_order_relaxed);
  }
}

void* probe_malloc(std::size_t n) {
  void* p = std::malloc(n ? n : 1);
  if (!p) throw std::bad_alloc();
  probe_count(n);
  return p;
}

}  // namespace

void* operator new(std::size_t n) { return probe_malloc(n); }
void* operator new[](std::size_t n) { return probe_malloc(n); }

// nothrow flavors (simdjson uses new[](nothrow) for its padded buffers):
// without these, allocation would come from the default operator new while
// the matching user-defined delete[] frees with free() → mismatch.
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
  void* p = std::malloc(n ? n : 1);
  if (p) probe_count(n);
  return p;
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept {
  void* p = std::malloc(n ? n : 1);
  if (p) probe_count(n);
  return p;
}

void* operator new(std::size_t n, std::align_val_t a) {
  void* p = nullptr;
#if defined(_WIN32)
  p = ::_aligned_malloc(n ? n : 1, static_cast<std::size_t>(a));
#else
  // C11: round the size up to a multiple of the alignment
  const std::size_t al = static_cast<std::size_t>(a);
  const std::size_t sz = (n + al - 1) & ~(al - 1);
  p = std::aligned_alloc(al, sz ? sz : al);
#endif
  if (!p) throw std::bad_alloc();
  probe_count(n);
  return p;
}

void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept {
#if defined(_WIN32)
  ::_aligned_free(p);
#else
  std::free(p);
#endif
}
void operator delete(void* p, std::size_t, std::align_val_t a) noexcept {
  operator delete(p, a);
}
void operator delete[](void* p, std::align_val_t) noexcept {
  operator delete(p, std::align_val_t{});
}
void operator delete[](void* p, std::size_t, std::align_val_t a) noexcept {
  operator delete(p, a);
}
void operator delete(void* p, const std::nothrow_t&) noexcept {
  std::free(p);
}
void operator delete[](void* p, const std::nothrow_t&) noexcept {
  std::free(p);
}

namespace fw {
// ---------------------------------------------------------------------------
// Self-tests
// ---------------------------------------------------------------------------
namespace h2 {
bool run_h2_selftests(int& pass, int& fail);  // defined in selftest_h2.cpp
}

bool run_selftest() {
  int pass = 0, fail = 0;
  auto check = [&](bool ok, std::string_view name) {
    if (ok) {
      ++pass;
    } else {
      ++fail;
      std::fprintf(stderr, "  FAIL: %.*s\n", int(name.size()), name.data());
    }
  };

  // string utils
  check(to_lower_ascii("CoNtEnT-Type") == "content-type", "to_lower_ascii");
  check(ieq_ascii("Content-Length", "content-length"), "ieq_ascii");
  check(trim_ows("  a b\t") == "a b", "trim_ows");
  check(is_tchar('a') && is_tchar('!') && !is_tchar(' '), "is_tchar");
  check(sanitize_header_value("a\r\nb: 1") == "ab: 1", "sanitize_header_value");
  check(html_escape("<script>&'\"") ==
            "&lt;script&gt;&amp;&#39;&quot;", "html_escape");

  // percent decoding
  check(percent_decode("/a%20b", false).value_or("") == "/a b", "percent_decode ok");
  check(!percent_decode("%zz", false).has_value(), "percent_decode bad hex");
  check(!percent_decode("%0", false).has_value(), "percent_decode truncated");
  check(!percent_decode("%00", false).has_value(), "percent_decode NUL");
  check(percent_decode("a+b", true).value_or("") == "a b", "percent_decode plus");

  // parse_num
  check(parse_num<int>("123").value_or(-1) == 123, "parse_num ok");
  check(parse_num<long long>("-9007199254740993").value_or(0) == -9007199254740993LL,
        "parse_num negative");
  check(!parse_num<int>("12a").has_value(), "parse_num trailing");
  check(!parse_num<int>("").has_value(), "parse_num empty");
  check(!parse_num<std::uint8_t>("256").has_value(), "parse_num range");

  // json
  {
    auto v = json::parse(R"({"a":1,"b":[true,null,-2.5],"c":"x\ny","d":{"e":"\u00e9"}})");
    check(v.has_value(), "json parse object");
    if (v) {
      check(v->find("a")->num() == 1, "json number");
      check(v->find("b")->as_array()->size() == 3, "json array");
      check(v->find("c")->str() == "x\ny", "json escape");
      check(v->find("d")->find("e")->str() == "\xC3\xA9", "json \\u00e9");
    }
    auto r = json::parse(R"({"s":"\ud83d\ude00"})");  // 😀 surrogate pair
    check(r && r->find("s")->str() == "\xF0\x9F\x98\x80", "json surrogate pair");
    check(json::parse("[1,2]").has_value(), "json array top");
    check(!json::parse("[1,2]x").has_value(), "json trailing garbage");
    check(!json::parse("[1,").has_value(), "json truncated");
    check(!json::parse("\"\\ud800\"").has_value(), "json lone surrogate");
    check(!json::parse("{'a':1}").has_value(), "json single quotes");
    std::string ser = json::serialize(json::Value::obj(
        {{"k", json::Value("v\"1")}, {"n", json::Value(42.0)}}));
    check(ser == R"({"k":"v\"1","n":42})", "json serialize");
  }

  // sse framing
  {
    const std::string e = sse_event("message", "l1\nl2", "42");
    check(e == "id: 42\nevent: message\ndata: l1\ndata: l2\n\n", "sse_event");
    check(sse_event("", "hi") == "data: hi\n\n", "sse_event default");
  }

  // status / mime
  check(http_status_text(431) == "Request Header Fields Too Large", "status text");
  check(mime_for("a.B.png") == "image/png", "mime png");
  check(mime_for("x.unknownext") == "application/octet-stream", "mime default");

  // request target parsing
  {
    Request r;
    r.target = "/a%20b?x=1&y=a%20b&z=a+b";
    check(!init_request_target(r).has_value(), "target ok");
    check(r.path == "/a b", "target path decoded");
    check(r.query_param("x") && *r.query_param("x") == "1" &&
              r.query_param("y") && *r.query_param("y") == "a b" &&
              r.query_param("z") && *r.query_param("z") == "a b",
          "query decoded");
    // flat storage: duplicate keys keep first position, last value (map
    // semantics preserved by field_set)
    r.set_query("x", "2");
    check(r.query.size() == 3 && *r.query_param("x") == "2",
          "fields set_* duplicate semantics");
    Request r2;
    r2.target = "http://example.com/p?q=1";
    check(!init_request_target(r2).has_value() && r2.path == "/p", "absolute-form");
    Request r3;
    r3.target = "not-a-target";
    check(init_request_target(r3).has_value(), "bad target rejected");
    Request r4;
    r4.target = "/x%0";
    check(init_request_target(r4).has_value(), "bad escape rejected");
  }

  // cached Date header (per-second, zero alloc steady state)
  {
    const std::string_view d1 = http_date_now();
    const std::string_view d2 = http_date_now();
    check(d1.size() == 29 && d1.substr(25) == " GMT" &&
              (d1 == d2 || d1.substr(0, 18) == d2.substr(0, 18)),
          "http_date_now cached format");
  }

  // ---- arena (fw/arena.hpp) --------------------------------------------------
  {
    Arena a;
    const auto v1 = a.store("hello");
    const auto v2 = a.store("world");
    check(v1 == "hello" && v2 == "world", "arena store/views");
    check((reinterpret_cast<std::uintptr_t>(a.allocate(7)) & 0xf) == 0,
          "arena max_align alignment");
    const std::string big(9000, 'x');
    const auto v3 = a.store(big);
    check(v3 == big && a.chunk_count() >= 2, "arena grows past first chunk");
    check(v1 == "hello" && v2 == "world",
          "arena views stable across growth");
    check(a.bytes_retained() >= Arena::kFirstChunkBytes &&
              a.bytes_retained() <= Arena::kKeepMaxBytes,
          "arena reset retains one small chunk");
    a.reset();
    check(a.bytes_in_use() == 0 && a.chunk_count() == 1, "arena reset reclaims");
    const auto v4 = a.store("after-reset");
    check(v4 == "after-reset", "arena usable after reset");
    const auto m = a.store("movable");
    Arena b = std::move(a);
    check(m == "movable", "arena views survive move");
    // oversized request → dedicated chunk, reset drops it (> keep cap)
    const std::string huge(64 * 1024, 'h');
    (void)b.store(huge);
    const std::size_t before = b.bytes_retained();
    b.reset();
    check(b.bytes_retained() <= before && b.bytes_in_use() == 0,
          "arena reset drops oversized chunks");
  }

  // ---- allocation-count regressions (fw/detail/mem_probe.hpp) -----------------
  {
    using fw::detail::MemProbe;
    // warm-up (one-time growth, thread-local date cache)
    {
      Request r;
      r.target = "/a/b?x=1&y=2&z=3";
      (void)init_request_target(r);
    }
    std::int64_t n = -1;
    {
      MemProbe pr;
      Request r;
      r.target = "/a/b?x=1&y=2&z=3";
      (void)init_request_target(r);
      check(r.query_param("x") && *r.query_param("x") == "1",
            "probe target parsed");
      n = pr.allocs();
    }
    check(n <= 6, "request-target parse allocations <= 6");
    if (n > 0)
      std::fprintf(stderr, "  (probe: target parse = %lld allocs)\n",
                   static_cast<long long>(n));
  }

  // router
  {
    Router rt;
    bool ok = true;
    try {
      rt.add("GET", "/", Handler{[](HttpCtx&) -> asio::awaitable<void> { co_return; }});
      rt.add("GET", "/posts/:id<uint32>", Handler{[](HttpCtx&) -> asio::awaitable<void> { co_return; }});
      rt.add("GET", "/files/*rest", Handler{[](HttpCtx&) -> asio::awaitable<void> { co_return; }});
      rt.add("POST", "/posts", Handler{[](HttpCtx&) -> asio::awaitable<void> { co_return; }});
    } catch (...) { ok = false; }
    check(ok, "router add");
    Fields p;
    auto pget = [&p](std::string_view k) -> const std::string* {
      return field_get(p, k);
    };
    bool mismatch = false;
    check(rt.match("GET", "/", p, mismatch) != nullptr, "router static");
    const Router::Route* r1 = rt.match("GET", "/posts/77", p, mismatch);
    check(r1 != nullptr && pget("id") && *pget("id") == "77", "router param");
    check(rt.match("GET", "/posts/-1", p, mismatch) == nullptr, "router typed reject");
    mismatch = false;
    check(rt.match("DELETE", "/posts", p, mismatch) == nullptr && mismatch,
          "router 405");
    p.clear();
    const Router::Route* r2 = rt.match("GET", "/files/a/b/c", p, mismatch);
    check(r2 != nullptr && pget("rest") && *pget("rest") == "a/b/c", "router wildcard");
    check(rt.match("GET", "/nope", p, mismatch) == nullptr && !mismatch, "router 404");
    bool threw = false;
    try { rt.add("GET", "/bad<>", Handler{}); } catch (...) { threw = true; }
    check(threw, "router invalid pattern");
  }

  // tokens
  const std::string t1 = random_token(16), t2 = random_token(16);
  check(t1.size() == 32 && t2.size() == 32 && t1 != t2, "random_token");

  // multipart
  {
    const std::string body =
        "--BND\r\n"
        "content-disposition: form-data; name=\"token\"\r\n\r\n"
        "abc123\r\n"
        "--BND\r\n"
        "content-disposition: form-data; name=\"file\"; filename=\"a b&c.png\"\r\n"
        "content-type: image/png\r\n\r\n"
        "\x89PNG-data\r\n"
        "--BND--\r\n";
    auto b = multipart_boundary_of("multipart/form-data; boundary=BND");
    check(b.has_value() && *b == "BND", "multipart boundary");
    auto mp = multipart_parse(body, "BND");
    check(mp.success(), "multipart parse ok");
    check(mp.field("token") == "abc123", "multipart field");
    const MultipartFile* f = mp.file("file");
    check(f && f->filename == "a b&c.png" && f->data == "\x89PNG-data",
          "multipart file");
    check(!multipart_parse("garbage", "BND").success(), "multipart garbage");
    check(!multipart_boundary_of("text/plain").has_value(),
          "multipart wrong content type");
    check(!multipart_boundary_of(
              "multipart/form-data; boundary=" + std::string(80, 'x'))
              .has_value(),
          "multipart boundary too long");
    // framing: content that contains a "--" line must not confuse the parser
    const std::string tricky =
        "--B\r\ncontent-disposition: form-data; name=\"x\"\r\n\r\n"
        "line\r\n--not-a-boundary\r\nstill x\r\n--B--\r\n";
    auto mp2 = multipart_parse(tricky, "B");
    check(mp2.success() && mp2.field("x") == "line\r\n--not-a-boundary\r\nstill x",
          "multipart boundary precision");
  }

  // upload filename hygiene
  {
    check(chat::safe_storage_name("1712345_ab-c.png"), "safe_storage_name ok");
    check(!chat::safe_storage_name("../x"), "safe_storage_name traversal");
    check(!chat::safe_storage_name(".env"), "safe_storage_name hidden");
    check(!chat::safe_storage_name("a/b.png"), "safe_storage_name slash");
    check(chat::sanitize_upload_filename("../../e\\vil<b>.pn-g") ==
              "_.._e_vil_b_.pn-g",
          "sanitize_upload_filename");
  }

  // HTTP/2: HPACK (RFC 7541 Appendix C conformance), framing, engine scenarios
  {
    h2::run_h2_selftests(pass, fail);
  }

  std::fprintf(stderr, "selftest: %d passed, %d failed\n", pass, fail);
  return fail == 0;
}
}  // namespace fw
