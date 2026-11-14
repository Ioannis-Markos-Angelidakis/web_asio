// ============================================================================
// app/selftest_h2.cpp — HTTP/2 self-tests: HPACK conformance against the
// RFC 7541 Appendix C vectors (incl. Huffman + dynamic-table eviction),
// primitive round-trips, framing, and scripted H2Conn engine scenarios.
// Pure — no sockets needed; the engine is fed bytes directly.
// ============================================================================

#include "fw/fw.hpp"
#include "fw/h2_conn.hpp"
#include "fw/h2_frame.hpp"
#include "fw/h2_hpack.hpp"

#include <cstring>

namespace fw::h2 {
namespace {

using hpack::Decoder;
using hpack::Encoder;

[[nodiscard]] std::vector<std::pair<std::string, std::string>> dec_hex(
    std::string_view hex, Decoder& d) {
  std::string raw;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    const auto nib = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      return c - 'a' + 10;
    };
    raw.push_back(char((nib(hex[i]) << 4) | nib(hex[i + 1])));
  }
  std::vector<std::pair<std::string, std::string>> out;
  d.decode(raw, 100, 64 * 1024, out);
  return out;
}

[[nodiscard]] std::string as_str(
    const std::vector<std::pair<std::string, std::string>>& v) {
  std::string s;
  for (const auto& [n, val] : v) s += n + "=" + val + ";";
  return s;
}

// ---- engine test harness ----------------------------------------------------
struct Ev : H2ConnEvents {
  int begins = 0, ends = 0, closes = 0, refused = 0;
  std::string method, target, authority, body;
  bool on_begin_request(std::uint32_t) override { ++begins; return true; }
  void on_header(std::uint32_t, std::string_view n, std::string_view v) override {
    if (n == ":method") method = std::string(v);
    else if (n == ":path") target = std::string(v);
    else if (n == ":authority") authority = std::string(v);
  }
  void on_headers_end(std::uint32_t, bool, bool) override {}
  bool on_data(std::uint32_t, std::string_view p) override { body.append(p); return true; }
  void on_end_stream(std::uint32_t) override { ++ends; }
  void on_stream_close(std::uint32_t, std::uint32_t code) override {
    ++closes;
    if (code == frame::kRefusedStream) ++refused;
  }
  void on_goaway() override {}
  void on_sendq_empty(std::uint32_t) override {}
  void on_progress() override {}
};

[[nodiscard]] std::string cli(std::string payload = {}) {
  // client preface + empty SETTINGS (+ optional extra payload)
  std::string s(kPreface);
  frame::append(s, frame::kSettings, 0, 0, {});
  s += payload;
  return s;
}

[[nodiscard]] std::size_t count_frames(std::string_view raw, std::uint8_t type,
                                       std::uint8_t flags = 0xff) {
  std::size_t n = 0, i = 0;
  while (i + 9 <= raw.size()) {
    const auto len = (std::uint32_t(std::uint8_t(raw[i])) << 16) |
                     (std::uint32_t(std::uint8_t(raw[i + 1])) << 8) |
                     std::uint32_t(std::uint8_t(raw[i + 2]));
    const auto t = std::uint8_t(raw[i + 3]);
    const auto fl = std::uint8_t(raw[i + 4]);
    if (t == type && (flags == 0xff || (fl & flags))) ++n;
    i += 9 + len;
  }
  return n;
}

[[nodiscard]] bool find_goaway(std::string_view raw, std::uint32_t& code) {
  for (std::size_t i = 0; i + 9 <= raw.size();) {
    const auto len = (std::uint32_t(std::uint8_t(raw[i])) << 16) |
                     (std::uint32_t(std::uint8_t(raw[i + 1])) << 8) |
                     std::uint32_t(std::uint8_t(raw[i + 2]));
    if (std::uint8_t(raw[i + 3]) == frame::kGoaway && len >= 8) {
      code = (std::uint32_t(std::uint8_t(raw[i + 13])) << 24) |
             (std::uint32_t(std::uint8_t(raw[i + 14])) << 16) |
             (std::uint32_t(std::uint8_t(raw[i + 15])) << 8) |
             std::uint32_t(std::uint8_t(raw[i + 16]));
      return true;
    }
    i += 9 + len;
  }
  return false;
}

std::string hpack_plain(std::initializer_list<std::pair<std::string_view,
                                                        std::string_view>> kv) {
  std::string out;
  for (const auto& [n, v] : kv) {
    out.push_back('\x00');  // literal w/o indexing, new name
    hpack::encode_uint(out, n.size(), 7, 0x00);
    out.append(n);
    hpack::encode_uint(out, v.size(), 7, 0x00);
    out.append(v);
  }
  return out;
}

}  // namespace

bool run_h2_selftests(int& pass, int& fail) {
  auto check = [&](bool ok, std::string_view name) {
    if (ok) ++pass;
    else {
      ++fail;
      std::fprintf(stderr, "  FAIL: %.*s\n", int(name.size()), name.data());
    }
  };

  // ---- HPACK integer + huffman primitives -----------------------------------
  {
    std::string buf;
    hpack::encode_uint(buf, 5, 5, 0x00);
    std::string_view v = buf;
    std::uint64_t got = 0;
    check(hpack::decode_uint(v, 5, got) && got == 5 && v.empty(),
          "hpack int small");
    buf.clear();
    hpack::encode_uint(buf, 1337, 5, 0x00);
    v = buf;
    check(hpack::decode_uint(v, 5, got) && got == 1337, "hpack int 1337");
    std::string all;
    for (int i = 0; i < 256; ++i) all.push_back(char(std::uint8_t(i)));
    const std::string h = hpack::huffman_encode(all);
    std::string back;
    check(hpack::huffman_decode(h, back) && back == all,
          "huffman round-trip over all 256 bytes");
    std::string bad;
    check(!hpack::huffman_decode(std::string("\xff\xff\xff\xff\xff", 5), bad),
          "huffman rejects overlong 1s (EOS-only)");
  }

  // ---- RFC 7541 Appendix C.4: requests with Huffman -------------------------
  // (the three blocks share one decoder — the dynamic table carries over)
  {
    Decoder d4;
    auto v1 = dec_hex("828684418cf1e3c2e5f23a6ba0ab90f4ff", d4);
    check(as_str(v1) ==
              ":method=GET;:scheme=http;:path=/;:authority=www.example.com;",
          "RFC C.4.1 huffman request");
    // C.4.2 reuses the dynamic entry (be = :authority from the table)
    auto v2 = dec_hex("828684be5886a8eb10649cbf", d4);
    check(as_str(v2) == ":method=GET;:scheme=http;:path=/;"
                        ":authority=www.example.com;cache-control=no-cache;",
          "RFC C.4.2 dynamic-table reuse");
    auto v3 = dec_hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", d4);
    check(as_str(v3) == ":method=GET;:scheme=https;:path=/index.html;"
                        ":authority=www.example.com;custom-key=custom-value;",
          "RFC C.4.3 custom header");
  }

  // ---- RFC 7541 Appendix C.5/C.6: responses incl. eviction ------------------
  {
    Decoder d5;
    auto r1 = dec_hex("4803333032580770726976617465611d4d6f6e2c203231204f637420"
                      "323031332032303a31333a323120474d546e1768747470733a2f2f77"
                      "77772e6578616d706c652e636f6d", d5);
    check(as_str(r1).starts_with(":status=302;cache-control=private;") &&
              as_str(r1).find("location=https://www.example.com;") !=
                  std::string::npos,
          "RFC C.5.1 response");
    auto r2 = dec_hex("4803333037c1c0bf", d5);
    check(as_str(r2) ==
              ":status=307;cache-control=private;"
              "date=Mon, 21 Oct 2013 20:13:21 GMT;"
              "location=https://www.example.com;",
          "RFC C.5.2 indexed reuse");
    auto r3 = dec_hex("88c1611d4d6f6e2c203231204f637420323031332032303a31333a32"
                      "3220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a"
                      "584f5157454f50495541585157454f49553b206d61782d6167653d33"
                      "3630303b2076657273696f6e3d31", d5);
    check(as_str(r3).starts_with(":status=200;") &&
              as_str(r3).find("content-encoding=gzip;") != std::string::npos &&
              as_str(r3).find("set-cookie=foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; "
                              "max-age=3600; version=1;") != std::string::npos,
          "RFC C.5.3 eviction");
    Decoder d6;  // C.6 sequence: Huffman responses (table state carries over)
    auto h1 = dec_hex("488264025885aec3771a4b6196d07abe941054d444a8200595040b8"
                      "166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3", d6);
    check(as_str(h1).starts_with(":status=302;") &&
              as_str(h1).find("location=https://www.example.com;") !=
                  std::string::npos,
          "RFC C.6.1 huffman response");
    auto h2v = dec_hex("4883640effc1c0bf", d6);
    check(as_str(h2v) ==
              ":status=307;cache-control=private;"
              "date=Mon, 21 Oct 2013 20:13:21 GMT;"
              "location=https://www.example.com;",
          "RFC C.6.2 huffman indexed reuse");
    auto h3 = dec_hex("88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a"
                      "839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f36"
                      "72c1ab270fb5291f9587316065c003ed4ee5b1063d5007", d6);
    check(as_str(h3).starts_with(":status=200;") &&
              as_str(h3).find("content-encoding=gzip;") != std::string::npos,
          "RFC C.6.3 huffman eviction");
  }

  // ---- encoder → decoder round-trip ------------------------------------------
  {
    Encoder enc;
    std::string buf;
    enc.encode(":status", "200", buf);
    enc.encode("content-type", "text/event-stream; charset=utf-8", buf);
    enc.encode("x-custom", "quotes \" and \x7f", buf);
    Decoder dec;
    std::vector<std::pair<std::string, std::string>> out;
    check(dec.decode(buf, 100, 64 * 1024, out).empty() && out.size() == 3 &&
              out[0].first == ":status" && out[0].second == "200" &&
              out[2].second == "quotes \" and \x7f",
          "encoder → decoder round-trip");
  }

  // ---- framing ----------------------------------------------------------------
  {
    std::string buf;
    frame::append(buf, frame::kData, frame::kEndStream | frame::kPadded, 7,
                  "hello");
    const frame::Header hd = frame::parse_header(buf.data());
    check(hd.len == 5 && hd.type == frame::kData && hd.id == 7 &&
              (hd.flags & frame::kEndStream) && (hd.flags & frame::kPadded),
          "frame header round-trip");
  }

  // ---- engine: handshake, PING, request/response, flow control -----------------
  {
    H2EngineLimits lim;
    lim.max_concurrent_streams = 3;
    Ev ev;
    H2Conn conn(lim, ev);
    conn.start();
    check(count_frames(conn.output(), frame::kSettings) == 1 &&
              count_frames(conn.output(), frame::kWindowUpdate) == 1,
          "engine start(): SETTINGS + WINDOW_UPDATE");

    check(conn.feed(cli().data(), cli().size()), "preface+SETTINGS accepted");
    check(count_frames(conn.output(), frame::kSettings, frame::kAck) == 1,
          "SETTINGS acknowledged");

    std::string ping = "pingpong";
    std::string pf;
    frame::append(pf, frame::kPing, 0, 0, ping);
    conn.feed(pf.data(), pf.size());
    check(count_frames(conn.output(), frame::kPing, frame::kAck) == 1,
          "PING echoed as ACK");

    // GET /health with END_STREAM → dispatch → respond
    std::string heads;
    frame::append(heads, frame::kHeaders, frame::kEndHeaders | frame::kEndStream,
                  1, hpack_plain({{":method", "GET"},
                                  {":path", "/health"},
                                  {":scheme", "http"},
                                  {":authority", "localhost"}}));
    check(conn.feed(heads.data(), heads.size()), "HEADERS accepted");
    check(ev.begins == 1 && ev.ends == 1 && ev.method == "GET" &&
              ev.target == "/health",
          "request events fired");
    conn.submit_response(1, {{":status", "200"},
                             {"content-type", "application/json"}},
                         false);
    conn.submit_data(1, "{\"status\":\"ok\"}", true);
    conn.produce();
    check(count_frames(conn.output(), frame::kHeaders) == 1 &&
              count_frames(conn.output(), frame::kData) >= 1,
          "response HEADERS + DATA produced");
    check(count_frames(conn.output(), frame::kData, frame::kEndStream) == 1,
          "final DATA carries END_STREAM");

    // flow control: 300 KiB body against the default 65535 window
    H2Conn c2(lim, ev);
    c2.start();
    c2.feed(cli().data(), cli().size());
    std::string h2f;
    frame::append(h2f, frame::kHeaders, frame::kEndHeaders | frame::kEndStream, 1,
                  hpack_plain({{":method", "GET"}, {":path", "/"},
                               {":scheme", "http"}, {":authority", "l"}}));
    c2.feed(h2f.data(), h2f.size());
    std::string big(300 * 1024, 'x');
    c2.submit_response(1, {{":status", "200"}}, false);
    c2.submit_data(1, big, true);
    c2.produce();
    std::size_t data_bytes = 0;
    for (std::size_t i = 0; i + 9 <= c2.output().size();) {
      const auto len = (std::uint32_t(std::uint8_t(c2.output()[i])) << 16) |
                       (std::uint32_t(std::uint8_t(c2.output()[i + 1])) << 8) |
                       std::uint32_t(std::uint8_t(c2.output()[i + 2]));
      if (std::uint8_t(c2.output()[i + 3]) == frame::kData) data_bytes += len;
      i += 9 + len;
    }
    check(data_bytes <= 65535 && data_bytes > 60000,
          "flow window caps initial DATA (default 65535)");
    std::string wu;
    frame::append(wu, frame::kWindowUpdate, 0, 0, std::string("\x00\x0f\x00\x01", 4));
    c2.feed(wu.data(), wu.size());
    std::string wu2;
    frame::append(wu2, frame::kWindowUpdate, 0, 1, std::string("\x00\x0f\x00\x01", 4));
    c2.feed(wu2.data(), wu2.size());
    c2.produce();
    data_bytes = 0;
    for (std::size_t i = 0; i + 9 <= c2.output().size();) {
      const auto len = (std::uint32_t(std::uint8_t(c2.output()[i])) << 16) |
                       (std::uint32_t(std::uint8_t(c2.output()[i + 1])) << 8) |
                       std::uint32_t(std::uint8_t(c2.output()[i + 2]));
      if (std::uint8_t(c2.output()[i + 3]) == frame::kData) data_bytes += len;
      i += 9 + len;
    }
    check(data_bytes > 65535, "WINDOW_UPDATE unlocks more DATA");

    // concurrency limit (max 3): 5 requests → 2 REFUSED_STREAM
    H2Conn c3(lim, ev);
    c3.start();
    c3.feed(cli().data(), cli().size());
    for (int i = 0; i < 5; ++i) {
      std::string hb;
      frame::append(hb, frame::kHeaders, frame::kEndHeaders, 2 * i + 1,
                    hpack_plain({{":method", "GET"}, {":path", "/"},
                                 {":scheme", "http"}, {":authority", "l"}}));
      c3.feed(hb.data(), hb.size());
    }
    check(count_frames(c3.output(), frame::kRstStream) == 2 && ev.refused == 2,
          "concurrency limit → REFUSED_STREAM for excess");

    // malformed HPACK → connection error (GOAWAY COMPRESSION_ERROR)
    H2Conn c4(lim, ev);
    c4.start();
    c4.feed(cli().data(), cli().size());
    std::string bad;
    frame::append(bad, frame::kHeaders, frame::kEndHeaders | frame::kEndStream, 1,
                  std::string("\xbe", 1));  // indexed 63 → beyond empty table
    check(!c4.feed(bad.data(), bad.size()), "bad HPACK rejected");
    std::uint32_t code = 0;
    check(find_goaway(c4.output(), code) && code == frame::kCompressionError,
          "GOAWAY COMPRESSION_ERROR emitted");
  }

  return fail == 0;
}

}  // namespace fw::h2
