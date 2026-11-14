// ============================================================================
// fw/router.hpp — Router — ':name' / ':id<uint32>' typed params, '*rest' tails.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/hooks.hpp"
#include "fw/util.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// Router — "/api/posts/:id<uint32>" style patterns, "*rest" tail capture.
// ---------------------------------------------------------------------------
class Router {
 public:
  struct Route {
    std::string method;
    std::vector<std::string> segments;  // literal | ":name" | ":name<type>" | "*rest"
    Handler handler;
    std::size_t max_body = 0;  // 0 → App::limits.max_body_bytes
  };

  void add(std::string method, std::string pattern, Handler handler,
           std::size_t max_body = 0) {
    Route r;
    r.method = std::move(method);
    auto segs = split_pattern(pattern);
    if (!segs) {
      throw std::invalid_argument("invalid route pattern: " + pattern);
    }
    r.segments = std::move(*segs);
    r.handler = std::move(handler);
    r.max_body = max_body;
    routes_.push_back(std::move(r));
  }

  // Returns the matched route (filling params), or nullptr. If a path matches
  // some route but with a different method, *method_mismatch is set.
  // HEAD is answered by GET handlers (the response serializers strip the
  // body for HEAD, so this is safe and matches common framework behavior).
  const Route* match(std::string_view method, std::string_view path,
                     std::map<std::string, std::string, std::less<>>& params,
                     bool& method_mismatch) const {
    method_mismatch = false;
    const std::string m = (method == "HEAD") ? std::string("GET")
                                             : std::string(method);
    const auto segs = split_path(path);
    for (const auto& r : routes_) {
      std::map<std::string, std::string, std::less<>> mm;
      if (match_segments(r.segments, segs, mm)) {
        if (r.method != m) { method_mismatch = true; continue; }
        params = std::move(mm);
        return &r;
      }
    }
    return nullptr;
  }

 private:
  // Split pattern into segments; empty on invalid pattern.
  static std::optional<std::vector<std::string>> split_pattern(std::string_view p) {
    if (p.empty() || p.front() != '/') return std::nullopt;
    if (p == "/") return std::vector<std::string>{};  // root → no segments
    std::vector<std::string> out;
    std::size_t i = 1;
    while (i <= p.size()) {
      const std::size_t slash = p.find('/', i);
      std::string seg(p.substr(i, slash == std::string_view::npos
                                        ? std::string_view::npos
                                        : slash - i));
      if (seg.empty()) return std::nullopt;
      if (seg.starts_with('*')) {
        if (seg != "*rest" || slash != std::string_view::npos) return std::nullopt;
        out.push_back(seg);
        return out;  // must be last
      }
      if (seg.starts_with(':')) {
        const auto lt = seg.find('<');
        if (lt == std::string::npos) {
          if (seg.size() < 2) return std::nullopt;
          for (char c : seg.substr(1))
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
              return std::nullopt;
        } else {
          const std::string name = seg.substr(1, lt - 1);
          const std::string type = seg.substr(lt + 1, seg.size() - lt - 2);
          if (name.empty() || seg.back() != '>')
            return std::nullopt;
          static const std::set<std::string> valid_types = {
              "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32",
              "uint64", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64"};
          if (!valid_types.contains(type)) return std::nullopt;
        }
      } else {
        // literal segment — no ':' '*' '<'
        if (seg.find_first_of(":*<>") != std::string::npos) return std::nullopt;
      }
      out.push_back(std::move(seg));
      if (slash == std::string_view::npos) break;
      i = slash + 1;
    }
    return out;
  }

  static std::vector<std::string_view> split_path(std::string_view path) {
    std::vector<std::string_view> out;
    std::size_t i = 1;
    while (i < path.size()) {
      const std::size_t slash = path.find('/', i);
      const std::size_t end = (slash == std::string_view::npos) ? path.size() : slash;
      out.push_back(path.substr(i, end - i));
      i = end + 1;
    }
    return out;
  }

  static bool match_segments(const std::vector<std::string>& pat,
                             const std::vector<std::string_view>& segs,
                             std::map<std::string, std::string, std::less<>>& out) {
    std::size_t i = 0;
    for (; i < pat.size(); ++i) {
      const std::string& ps = pat[i];
      if (ps == "*rest") {
        std::string rest;
        for (std::size_t k = i; k < segs.size(); ++k) {
          if (k > i) rest += '/';
          rest += std::string(segs[k]);
        }
        out.emplace("rest", std::move(rest));
        return true;
      }
      if (i >= segs.size()) return false;
      if (ps.starts_with(':')) {
        const auto lt = ps.find('<');
        const std::string_view val = segs[i];
        if (lt != std::string::npos) {
          const std::string type = ps.substr(lt + 1, ps.size() - lt - 2);
          const bool ok = check_typed(type, val);
          if (!ok) return false;
        }
        out.emplace(ps.substr(1, lt == std::string::npos ? std::string::npos
                                                         : lt - 1),
                    std::string(val));
      } else {
        if (ps != segs[i]) return false;
      }
    }
    return i == segs.size();
  }

  static bool check_typed(const std::string& type, std::string_view v) {
    auto ok = []<class T>(std::string_view s) {
      return parse_num<T>(s).has_value();
    };
    if (type == "int8" || type == "i8")   return ok.template operator()<std::int8_t>(v);
    if (type == "int16" || type == "i16") return ok.template operator()<std::int16_t>(v);
    if (type == "int32" || type == "i32") return ok.template operator()<std::int32_t>(v);
    if (type == "int64" || type == "i64") return ok.template operator()<std::int64_t>(v);
    if (type == "uint8" || type == "u8")  return ok.template operator()<std::uint8_t>(v);
    if (type == "uint16" || type == "u16")return ok.template operator()<std::uint16_t>(v);
    if (type == "uint32" || type == "u32")return ok.template operator()<std::uint32_t>(v);
    if (type == "uint64" || type == "u64")return ok.template operator()<std::uint64_t>(v);
    return false;
  }

  std::vector<Route> routes_;
};

}  // namespace fw
