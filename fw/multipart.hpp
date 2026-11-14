// ============================================================================
// fw/multipart.hpp — Strict RFC 2046 multipart/form-data framing parser (bounded parts/headers, validated boundary).
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"
#include "fw/util.hpp"

namespace fw {
// ---------------------------------------------------------------------------
// multipart/form-data — strict RFC 2046 framing parser (per-request state,
// bounded parts/headers). Boundary validation happens up front: length and
// charset per RFC 2046 §5.1.1, so the delimiter can never contain CR/LF or
// appear "by accident" inside content it did not delimit.
// ---------------------------------------------------------------------------
struct MultipartFile {
  std::string name;         // form field name ("file")
  std::string filename;     // original filename (UNTRUSTED)
  std::string content_type; // client MIME (UNTRUSTED, never trusted for
                            // inline rendering)
  std::string data;
  std::size_t size() const { return data.size(); }
  bool empty() const { return data.empty(); }
};

struct MultipartField {
  std::string name;
  std::string value;
};

struct MultipartResult {
  std::vector<MultipartField> fields;
  std::vector<MultipartFile> files;
  std::string error;
  bool success() const { return error.empty(); }
  std::string field(std::string_view n) const {
    for (const auto& f : fields)
      if (f.name == n) return f.value;
    return {};
  }
  const MultipartFile* file(std::string_view n) const {
    for (const auto& f : files)
      if (f.name == n) return &f;
    return nullptr;
  }
};

// Extract the boundary parameter from a Content-Type header value.
// The boundary itself is case-SENSITIVE — match the parameter name
// case-insensitively, but slice the value out of the original string.
inline std::expected<std::string, std::string> multipart_boundary_of(
    std::string_view content_type) {
  const std::string_view ct = trim_ows(content_type);
  if (!ieq_ascii(ct.substr(0, 19), "multipart/form-data"))
    return std::unexpected("not multipart/form-data");
  // case-insensitive search for "boundary="
  std::size_t pos = std::string_view::npos;
  for (std::size_t i = 19; i + 9 <= ct.size(); ++i) {
    if (ieq_ascii(ct.substr(i, 9), "boundary=")) {
      pos = i + 9;
      break;
    }
  }
  if (pos == std::string_view::npos)
    return std::unexpected("missing boundary parameter");
  std::string_view b = ct.substr(pos);
  if (!b.empty() && b.front() == '"') {
    const auto endq = b.find('"', 1);
    if (endq == std::string_view::npos)
      return std::unexpected("unterminated quoted boundary");
    b = b.substr(1, endq - 1);
  } else {
    const auto semi = b.find(';');
    if (semi != std::string_view::npos) b = b.substr(0, semi);
    b = trim_ows(b);
  }
  if (b.empty() || b.size() > 70)
    return std::unexpected("boundary must be 1-70 characters");
  for (const char c : b) {
    const bool ok = std::isalnum(static_cast<unsigned char>(c)) ||
                    std::string_view("'+-_{}|`^~%#$&*=.,;:?/<>[]() ")
                        .find(c) != std::string_view::npos;
    if (!ok) return std::unexpected("invalid character in boundary");
  }
  if (b.front() == ' ' || b.back() == ' ')
    return std::unexpected("boundary may not start/end with a space");
  return std::string(b);
}

// Parts are delimited by "\r\n--<boundary>" (the very first delimiter sits
// directly at offset 0), the closing delimiter ends in "--".
inline MultipartResult multipart_parse(std::string_view body,
                                       std::string_view boundary) {
  MultipartResult r;
  constexpr std::size_t kMaxParts = 64;
  const std::string dash_boundary =
      "--" + std::string(boundary);
  if (!body.starts_with(dash_boundary)) {
    r.error = "missing opening boundary";
    return r;
  }
  std::size_t pos = dash_boundary.size();
  while (pos < body.size()) {
    if (body.compare(pos, 2, "--") == 0) return r;  // closing delimiter
    if (body.compare(pos, 2, "\r\n") != 0) {
      r.error = "malformed boundary delimiter";
      return r;
    }
    pos += 2;
    if (r.fields.size() + r.files.size() >= kMaxParts) {
      r.error = "too many parts";
      return r;
    }
    const auto headers_end = body.find("\r\n\r\n", pos);
    if (headers_end == std::string::npos) {
      r.error = "unterminated part headers";
      return r;
    }
    const std::string_view headers_block = body.substr(pos, headers_end - pos);
    if (headers_block.size() > 16 * 1024) {
      r.error = "part headers too large";
      return r;
    }
    const std::string closing = "\r\n" + dash_boundary;
    const auto next = body.find(closing, headers_end + 4);
    if (next == std::string::npos) {
      r.error = "missing closing boundary";
      return r;
    }
    const std::string_view content =
        body.substr(headers_end + 4, next - (headers_end + 4));

    // ---- part headers (case-insensitive, tolerant line order) ----
    std::map<std::string, std::string, std::less<>> part_headers;
    std::string content_disposition;
    {
      std::size_t hpos = 0;
      while (hpos < headers_block.size()) {
        const auto eol = headers_block.find("\r\n", hpos);
        const std::string_view line =
            eol == std::string_view::npos
                ? headers_block.substr(hpos)
                : headers_block.substr(hpos, eol - hpos);
        hpos = (eol == std::string_view::npos) ? headers_block.size()
                                              : eol + 2;
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        const std::string key = to_lower_ascii(trim_ows(line.substr(0, colon)));
        const std::string value{trim_ows(line.substr(colon + 1))};
        part_headers[key] = value;
        if (key == "content-disposition") content_disposition = value;
      }
    }
    if (content_disposition.empty()) {
      r.error = "part without Content-Disposition";
      return r;
    }
    // ---- Content-Disposition params: name="x"; filename="y" ----
    const auto cd_param = [](const std::string& cd,
                             std::string_view want) -> std::string {
      std::size_t p = 0;
      while (p < cd.size()) {
        const auto semi = cd.find(';', p);
        const std::string_view seg =
            semi == std::string::npos
                ? std::string_view(cd).substr(p)
                : std::string_view(cd).substr(p, semi - p);
        p = (semi == std::string::npos) ? cd.size() : semi + 1;
        const auto eq = seg.find('=');
        if (eq == std::string_view::npos) continue;
        std::string_view key = trim_ows(seg.substr(0, eq));
        if (ieq_ascii(key, want)) {
          std::string_view val = trim_ows(seg.substr(eq + 1));
          if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
            val = val.substr(1, val.size() - 2);
          return std::string(val);
        }
      }
      return {};
    };
    const std::string field_name = cd_param(content_disposition, "name");
    const std::string filename = cd_param(content_disposition, "filename");
    if (field_name.empty()) {
      r.error = "part without a field name";
      return r;
    }
    if (!filename.empty()) {
      MultipartFile f;
      f.name = field_name;
      f.filename = filename;  // UNTRUSTED — sanitize before disk use
      if (const auto it = part_headers.find("content-type");
          it != part_headers.end())
        f.content_type = it->second;
      f.data = std::string(content);
      r.files.push_back(std::move(f));
    } else {
      r.fields.push_back(
          MultipartField{field_name, std::string(content)});
    }
    pos = next + closing.size();
  }
  return r;
}

}  // namespace fw
