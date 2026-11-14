// ============================================================================
// fw/json.hpp — JSON value model + serializer.
// Parsing is backed by bundled simdjson (third_party/simdjson) — see
// fw/json_parse.cpp; serialize/escape below is the built-in writer.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// JSON value model + serializer. The parser behind json::parse() is the
// bundled simdjson single-header build (SIMD, strict UTF-8/JSON validation);
// it lives in fw/json_parse.cpp so the huge simdjson.h is included once.
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

// Defined in fw/json_parse.cpp (simdjson backend). Declared — not defined
// inline — so the bundled simdjson.h is only ever included by that one TU.
// Semantics: strict JSON + UTF-8, insertion-ordered objects with duplicate
// keys preserved (find() returns the first), all numbers stored as double,
// nesting capped at 1024 (simdjson DEFAULT_MAX_DEPTH).
std::expected<Value, std::string> parse(std::string_view in);

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
