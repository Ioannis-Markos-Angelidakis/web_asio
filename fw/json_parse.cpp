// ============================================================================
// fw/json_parse.cpp — the JSON *parser* backend.
//
// Parsing is delegated to simdjson v5 (Apache-2.0 / MIT dual-licensed,
// bundled in third_party/simdjson as the official single-header release):
// the reference SIMD JSON parser — microparallel string/number scanning
// with runtime CPU dispatch (AVX-512 / AVX2 / SSE4.2 / NEON), strict JSON
// and UTF-8 validation, fuzzed by the upstream project for years. This TU
// is the only place simdjson.h is included, so its ~10 MB of headers are
// parsed exactly once per binary.
//
// The public API (fw/json.hpp) is unchanged:
//   * fw::json::Value — object order and duplicate keys preserved (find()
//     returns the first match); every number is stored as double.
//   * parse() returns std::expected<Value, std::string> with a
//     "json: <reason>" message on failure.
//
// Behavior notes vs. the hand-written parser this file replaces:
//   * Nesting cap is simdjson's DEFAULT_MAX_DEPTH (1024); the tape walk is
//     iterative inside simdjson and the conversion recursion below is
//     shallow enough that 1024 levels cannot overflow the stack.
//   * Lone \uD800-\uDFFF escapes and invalid UTF-8 are still rejected
//     (simdjson validates UTF-8 by default).
//   * Integers beyond 64-bit range still degrade to double, exactly like
//     the old from_chars-based number reader.
//   * simdjson's dom::parser is not thread-safe but is built for reuse:
//     one instance per thread (thread_local) is the intended fast path.
// ============================================================================

#include "fw/json.hpp"

#include <simdjson.h>

namespace fw::json {
namespace {

thread_local simdjson::dom::parser t_parser;

Value convert(simdjson::dom::element el) {
  using ET = simdjson::dom::element_type;
  switch (el.type()) {
    case ET::ARRAY: {
      Array a;
      // copy the handle out: dom::array is a lightweight view of the parser's
      // tape (outlives the simdjson_result temporary above).
      const simdjson::dom::array src = el.get_array().value();
      for (const auto item : src) a.push_back(convert(item));
      return Value(std::move(a));
    }
    case ET::OBJECT: {
      Object o;
      const simdjson::dom::object src = el.get_object().value();
      for (const auto& kv : src)
        o.emplace_back(std::string(kv.key), convert(kv.value));
      return Value(std::move(o));
    }
    case ET::INT64:
      return Value(static_cast<double>(el.get_int64().value()));
    case ET::UINT64:
      return Value(static_cast<double>(el.get_uint64().value()));
    case ET::DOUBLE:
      return Value(el.get_double().value());
    case ET::BOOL:
      return Value(el.get_bool().value());
    case ET::STRING:
      return Value(std::string(el.get_string().value()));
    case ET::NULL_VALUE:
    default:
      // BIGINT only appears with parser.number_as_string(true), which we
      // never enable; anything unexpected parses as null-like and keeps
      // convert() total.
      return Value(nullptr);
  }
}

}  // namespace

std::expected<Value, std::string> parse(std::string_view in) {
  if (in.empty())
    return std::unexpected(std::string("json: empty input"));
  if (in.size() > std::numeric_limits<std::uint32_t>::max())
    return std::unexpected(std::string("json: input too large (> 4 GiB)"));
  // (data, len) overload: simdjson sees the buffer is not padded and copies
  // it into its own padded storage — safe for any string_view we are handed.
  auto doc = t_parser.parse(in.data(), in.size());
  if (doc.error() != simdjson::SUCCESS)
    return std::unexpected("json: " +
                           std::string(simdjson::error_message(doc.error())));
  return convert(doc.value());
}

}  // namespace fw::json
