// ============================================================================
// fw/json.hpp — Minimal strict JSON parser + serializer (no dependencies).
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// Minimal, strict JSON (parser + serializer) — no external dependency.
// ---------------------------------------------------------------------------
namespace json {

class Value;
using Array  = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>;

class Value {
 public:
  enum class Kind { Null = 0, Bool, Number, String, Array, Object };

  Value() = default;
  Value(std::nullptr_t) {}
  Value(bool b) : v_(b) {}
  Value(double d) : v_(d) {}
  Value(const char* s) : v_(std::string(s)) {}
  Value(std::string s) : v_(std::move(s)) {}
  Value(Array a) : v_(std::move(a)) {}
  Value(Object o) : v_(std::move(o)) {}

  Kind kind() const { return static_cast<Kind>(v_.index()); }
  bool is_null()   const { return v_.index() == 0; }
  bool is_bool()   const { return v_.index() == 1; }
  bool is_number() const { return v_.index() == 2; }
  bool is_string() const { return v_.index() == 3; }
  bool is_array()  const { return v_.index() == 4; }
  bool is_object() const { return v_.index() == 5; }

  const Value* find(std::string_view key) const {
    if (!is_object()) return nullptr;
    for (const auto& [k, val] : std::get<Object>(v_))
      if (k == key) return &val;
    return nullptr;
  }
  std::string_view str(std::string_view def = "") const {
    if (const auto* p = std::get_if<std::string>(&v_)) return *p;
    return def;
  }
  double num(double def = 0) const {
    if (const auto* p = std::get_if<double>(&v_)) return *p;
    return def;
  }
  bool boolean(bool def = false) const {
    if (const auto* p = std::get_if<bool>(&v_)) return *p;
    return def;
  }
  const Array* as_array() const { return std::get_if<Array>(&v_); }
  const Object* as_object() const { return std::get_if<Object>(&v_); }

  static Value obj(Object o) { return Value(std::move(o)); }
  static Value arr(Array a) { return Value(std::move(a)); }

 private:
  std::variant<std::nullptr_t, bool, double, std::string, Array, Object> v_;
};

namespace detail {

struct Parser {
  std::string_view s;
  std::size_t i = 0;
  int depth = 0;

  [[noreturn]] void fail(const char* what) const {
    throw std::runtime_error(std::format("json: {} at offset {}", what, i));
  }

  void ws() {
    while (i < s.size()) {
      const char c = s[i];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++i; else break;
    }
  }

  char peek() const {
    if (i >= s.size()) fail("unexpected end of input");
    return s[i];
  }

  void expect(char c) {
    if (i >= s.size() || s[i] != c) fail("unexpected character");
    ++i;
  }

  static void utf8_encode(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7F) {
      out.push_back(char(cp));
    } else if (cp <= 0x7FF) {
      out.push_back(char(0xC0 | (cp >> 6)));
      out.push_back(char(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
      out.push_back(char(0xE0 | (cp >> 12)));
      out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(char(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(char(0xF0 | (cp >> 18)));
      out.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(char(0x80 | (cp & 0x3F)));
    }
  }

  std::uint32_t hex4() {
    if (i + 4 > s.size()) fail("truncated \\u escape");
    std::uint32_t v = 0;
    for (int k = 0; k < 4; ++k) {
      const char c = s[i++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= unsigned(c - '0');
      else if (c >= 'a' && c <= 'f') v |= unsigned(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= unsigned(c - 'A' + 10);
      else fail("invalid \\u escape");
    }
    return v;
  }

  std::string string() {
    expect('"');
    std::string out;
    for (;;) {
      if (i >= s.size()) fail("unterminated string");
      const char c = s[i++];
      if (c == '"') return out;
      if (static_cast<unsigned char>(c) < 0x20) fail("control char in string");
      if (c != '\\') { out.push_back(c); continue; }
      if (i >= s.size()) fail("unterminated escape");
      const char e = s[i++];
      switch (e) {
        case '"':  out.push_back('"');  break;
        case '\\': out.push_back('\\'); break;
        case '/':  out.push_back('/');  break;
        case 'b':  out.push_back('\b'); break;
        case 'f':  out.push_back('\f'); break;
        case 'n':  out.push_back('\n'); break;
        case 'r':  out.push_back('\r'); break;
        case 't':  out.push_back('\t'); break;
        case 'u': {
          std::uint32_t cp = hex4();
          if (cp >= 0xD800 && cp <= 0xDBFF) {  // high surrogate
            if (i + 2 > s.size() || s[i] != '\\' || s[i + 1] != 'u')
              fail("lone high surrogate");
            i += 2;
            const std::uint32_t lo = hex4();
            if (lo < 0xDC00 || lo > 0xDFFF) fail("invalid low surrogate");
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            fail("lone low surrogate");
          }
          utf8_encode(out, cp);
          break;
        }
        default: fail("invalid escape");
      }
    }
  }

  Value number() {
    const std::size_t start = i;
    if (i < s.size() && s[i] == '-') ++i;
    if (i >= s.size()) fail("invalid number");
    if (s[i] == '0') { ++i; }
    else if (std::isdigit(static_cast<unsigned char>(s[i]))) {
      while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
    } else fail("invalid number");
    if (i < s.size() && s[i] == '.') {
      ++i;
      if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i])))
        fail("invalid fraction");
      while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
    }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
      ++i;
      if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
      if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i])))
        fail("invalid exponent");
      while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
    }
    double d = 0;
    const char* first = s.data() + start;
    const char* last  = s.data() + i;
    const auto [ptr, ec] = std::from_chars(first, last, d);
    if (ec != std::errc{} || ptr != last) fail("invalid number");
    return Value(d);
  }

  Value value() {
    if (++depth > 64) fail("nesting too deep");
    const char c = peek();
    Value out;
    switch (c) {
      case '{': {
        ++i;
        Object obj;
        ws();
        if (peek() == '}') { ++i; break; }
        for (;;) {
          ws();
          if (peek() != '"') fail("expected object key");
          std::string key = string();
          ws();
          expect(':');
          ws();
          obj.emplace_back(std::move(key), value());
          ws();
          const char d = peek();
          if (d == ',') { ++i; continue; }
          if (d == '}') { ++i; break; }
          fail("expected ',' or '}'");
        }
        out = Value(std::move(obj));
        break;
      }
      case '[': {
        ++i;
        Array arr;
        ws();
        if (peek() == ']') { ++i; break; }
        for (;;) {
          ws();
          arr.push_back(value());
          ws();
          const char d = peek();
          if (d == ',') { ++i; continue; }
          if (d == ']') { ++i; break; }
          fail("expected ',' or ']'");
        }
        out = Value(std::move(arr));
        break;
      }
      case '"': out = Value(string()); break;
      case 't':
        if (s.substr(i, 4) != "true") fail("invalid literal");
        i += 4; out = Value(true); break;
      case 'f':
        if (s.substr(i, 5) != "false") fail("invalid literal");
        i += 5; out = Value(false); break;
      case 'n':
        if (s.substr(i, 4) != "null") fail("invalid literal");
        i += 4; out = Value(nullptr); break;
      default:
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c)))
          out = number();
        else
          fail("unexpected character");
        break;
    }
    --depth;
    return out;
  }
};

inline void escape_to(std::string& out, std::string_view s) {
  static constexpr char hex[] = "0123456789abcdef";
  for (unsigned char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out.push_back(hex[c >> 4]);
          out.push_back(hex[c & 0xF]);
        } else {
          out.push_back(char(c));
        }
    }
  }
}

}  // namespace detail

inline std::expected<Value, std::string> parse(std::string_view in) {
  try {
    detail::Parser p{in};
    p.ws();
    Value v = p.value();
    p.ws();
    if (p.i != p.s.size()) p.fail("trailing characters");
    return v;
  } catch (const std::exception& e) {
    return std::unexpected(std::string(e.what()));
  }
}

inline void serialize_to(std::string& out, const Value& v) {
  switch (v.kind()) {
    case Value::Kind::Null:   out += "null"; break;
    case Value::Kind::Bool:   out += v.boolean() ? "true" : "false"; break;
    case Value::Kind::Number: {
      const double d = v.num();
      if (std::isfinite(d) && d == std::floor(d) && std::fabs(d) < 9.0e15) {
        out += std::format("{}", static_cast<std::int64_t>(d));
      } else if (std::isfinite(d)) {
        out += std::format("{}", d);
      } else {
        out += "null";  // JSON has no NaN/Inf
      }
      break;
    }
    case Value::Kind::String:
      out += '"';
      detail::escape_to(out, v.str());
      out += '"';
      break;
    case Value::Kind::Array: {
      out += '[';
      bool first = true;
      if (const auto* a = v.as_array())
        for (const auto& item : *a) {
          if (!first) out += ',';
          first = false;
          serialize_to(out, item);
        }
      out += ']';
      break;
    }
    case Value::Kind::Object: {
      out += '{';
      bool first = true;
      if (const auto* o = v.as_object())
        for (const auto& [k, item] : *o) {
          if (!first) out += ',';
          first = false;
          out += '"';
          detail::escape_to(out, k);
          out += "\":";
          serialize_to(out, item);
        }
      out += '}';
      break;
    }
  }
}

inline std::string serialize(const Value& v) {
  std::string out;
  serialize_to(out, v);
  return out;
}

}  // namespace json
}  // namespace fw
