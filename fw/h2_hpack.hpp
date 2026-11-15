// ============================================================================
// fw/h2_hpack.hpp — HPACK (RFC 7541) header compression: static + dynamic
// tables, integer & string-literal primitives, canonical Huffman codec.
// Pure C++, no asio. The decoder is per-connection (dynamic-table state);
// the encoder is stateless (literal-without-indexing + Huffman, with an
// indexed fast path for exact static-table matches such as ":status: 200").
// Part of the from-scratch HTTP/2 implementation (no nghttp2).
// ============================================================================
#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fw/arena.hpp"
#include "fw/detail/base.hpp"
#include "fw/h2_hpack_tables.hpp"

namespace fw::h2::hpack {

// ---------------------------------------------------------------------------
// Integer primitive (RFC 7541 §5.1). Reads the first octet's low
// `prefix_bits` as the value; if that is the all-ones prefix, continues with
// 7-bit continuation bytes. `buf` advances past everything consumed. Never
// writes into the input — it only reads it.
// ---------------------------------------------------------------------------
inline bool decode_uint(std::string_view& buf, unsigned prefix_bits,
                        std::uint64_t& out) {
  if (buf.empty()) return false;
  const std::uint64_t max_prefix = (1ull << prefix_bits) - 1;
  const std::uint64_t v0 = std::uint8_t(buf.front()) & max_prefix;
  buf.remove_prefix(1);
  if (v0 < max_prefix) {
    out = v0;
    return true;
  }
  std::uint64_t v = v0, m = 0;
  for (unsigned bytes = 0;; ++bytes) {
    if (buf.empty() || bytes >= 5) return false;  // cap: value ≤ 2^32-1
    const std::uint8_t b = std::uint8_t(buf.front());
    buf.remove_prefix(1);
    v += std::uint64_t(b & 0x7f) << m;
    if ((b & 0x80) == 0) break;
    m += 7;
    if (m >= 63) return false;
  }
  if (v > 0xffffffffull) return false;
  out = v;
  return true;
}

inline void encode_uint(std::string& out, std::uint64_t v,
                        unsigned prefix_bits, std::uint8_t low_bits) {
  const std::uint64_t max_prefix = (1ull << prefix_bits) - 1;
  if (v < max_prefix) {
    out.push_back(char(low_bits | std::uint8_t(v)));
    return;
  }
  out.push_back(char(low_bits | std::uint8_t(max_prefix)));
  v -= max_prefix;
  while (v >= 128) {
    out.push_back(char(std::uint8_t((v & 0x7f) | 0x80)));
    v >>= 7;
  }
  out.push_back(char(std::uint8_t(v)));
}

// ---------------------------------------------------------------------------
// Huffman (RFC 7541 §5.2 / Appendix B). Codes are ≤ 30 bits.
// `huffman_decode` fails on an invalid path or on EOS appearing in the data;
// trailing bits must be an EOS prefix shorter than 8 bits (padding rule).
// ---------------------------------------------------------------------------
struct HuffNode {
  std::int32_t left = -1, right = -1;  // 0/1 child indices
  std::int32_t sym = -1;               // -1 = internal node
};

inline const std::vector<HuffNode>& huff_tree() {
  // Built once, immutable afterwards — safe to share across connections.
  // NB: everything is index-based; storing references/pointers into `t`
  // across an emplace_back would dangle (vector reallocates).
  static const std::vector<HuffNode> tree = [] {
    std::vector<HuffNode> t(1);  // root
    for (int sym = 0; sym <= 256; ++sym) {
      const auto [code, bits] = kHuffCode[sym];
      std::int32_t cur = 0;
      for (int i = int(bits) - 1; i >= 0; --i) {
        const bool bit = ((code >> i) & 1u) != 0;
        const std::int32_t next =
            bit ? t[std::size_t(cur)].right : t[std::size_t(cur)].left;
        if (next < 0) {
          t.emplace_back();
          const auto idx = std::int32_t(t.size() - 1);
          (bit ? t[std::size_t(cur)].right : t[std::size_t(cur)].left) = idx;
          cur = idx;
        } else {
          cur = next;
        }
      }
      t[std::size_t(cur)].sym = sym;
    }
    return t;
  }();
  return tree;
}

inline std::string huffman_encode(std::string_view raw) {
  std::string out;
  out.reserve(raw.size() + raw.size() / 2 + 4);
  std::uint64_t acc = 0;
  unsigned nbits = 0;
  for (char c : raw) {
    const auto& e = kHuffCode[std::uint8_t(c)];
    acc = (acc << e.bits) | e.code;
    nbits += e.bits;
    while (nbits >= 8) {
      nbits -= 8;
      out.push_back(char(std::uint8_t((acc >> nbits) & 0xff)));
    }
  }
  if (nbits != 0) {  // pad with the EOS prefix (all ones)
    const unsigned pad = 8 - nbits;
    acc = (acc << pad) | ((1ull << pad) - 1);
    out.push_back(char(std::uint8_t(acc & 0xff)));
  }
  return out;
}

inline bool huffman_decode(std::string_view bits, std::string& out) {
  const auto& t = huff_tree();
  out.clear();
  std::int32_t cur = 0;
  unsigned pending = 0;    // bits of the current (incomplete) symbol
  bool all_ones = true;    // is the partial path an EOS prefix?
  for (char c : bits) {
    const std::uint8_t b = std::uint8_t(c);
    for (int i = 7; i >= 0; --i) {
      const bool bit = ((b >> i) & 1u) != 0;
      cur = bit ? t[std::size_t(cur)].right : t[std::size_t(cur)].left;
      if (cur < 0) return false;  // no such code
      if (!bit) all_ones = false;
      ++pending;
      if (t[std::size_t(cur)].sym >= 0) {
        const auto sym = t[std::size_t(cur)].sym;
        if (sym == 256) return false;  // EOS may only appear as padding
        out.push_back(char(std::uint8_t(sym)));
        cur = 0;
        pending = 0;
        all_ones = true;
      }
    }
  }
  if (cur != 0) {  // partial symbol left: must be EOS padding, < 8 bits
    if (!all_ones || pending >= 8) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// String literal (§5.2): H flag + 7-bit length + payload (raw or Huffman).
// The view flavor decodes into arena-backed storage: plain literals and
// Huffman-decoded strings are copied into `scratch` (bump allocation, no
// per-string malloc) and handed back as stable views.
// ---------------------------------------------------------------------------
inline bool decode_string(std::string_view& buf, Arena& scratch,
                          std::string& huff_scratch,
                          std::string_view& out) {
  if (buf.empty()) return false;
  const bool huff = (std::uint8_t(buf.front()) & 0x80) != 0;
  std::uint64_t len = 0;
  if (!decode_uint(buf, 7, len)) return false;  // masks the H bit off
  if (len > buf.size()) return false;
  const std::string_view data = buf.substr(0, std::size_t(len));
  buf.remove_prefix(std::size_t(len));
  if (huff) {
    if (!huffman_decode(data, huff_scratch)) return false;
    out = scratch.store(huff_scratch);
  } else {
    out = scratch.store(data);
  }
  return true;
}

inline void encode_string(std::string& out, std::string_view v) {
  const std::string h = huffman_encode(v);
  if (h.size() < v.size()) {
    encode_uint(out, h.size(), 7, 0x80);
    out.append(h);
  } else {
    encode_uint(out, v.size(), 7, 0x00);
    out.append(v);
  }
}

// ---------------------------------------------------------------------------
// Decoder (per connection). A decode error is a *connection* error
// (RFC 7541 §4.3 → COMPRESSION_ERROR). Header count/size caps are enforced
// while decoding — the HPACK-bomb defense — so a hostile block can never
// balloon memory; the caller maps "too_large" to a stream refusal.
//
// decode() fills `out` with views that point into `scratch` (the caller's
// arena): stable until the arena is reset, immune to dynamic-table
// eviction, and allocation-free after the arena is warm. The caller copies
// them into its own storage (the engine does, synchronously, in
// on_header) before resetting the arena.
// ---------------------------------------------------------------------------
class Decoder {
 public:
  using Field = std::pair<std::string_view, std::string_view>;

  explicit Decoder(std::uint32_t table_max = 4096) : table_max_(table_max) {}

  // Returns "" on success; on failure a short tag: "compression"/"too_large".
  std::string decode(std::string_view buf, std::size_t max_headers,
                     std::size_t max_bytes,
                     std::vector<Field>& out, Arena& scratch);

  void set_table_max(std::uint32_t m) { table_max_ = m; }

  [[nodiscard]] bool lookup(std::uint64_t idx, std::string_view& n,
                            std::string_view& v) const {
    if (idx == 0) return false;
    if (idx <= kStaticTableSize) {
      n = kStaticTable[idx - 1].name;
      v = kStaticTable[idx - 1].value;
      return true;
    }
    const std::uint64_t d = idx - kStaticTableSize - 1;  // 0 = newest
    if (d >= dyn_.size()) return false;
    n = dyn_[std::size_t(d)].first;
    v = dyn_[std::size_t(d)].second;
    return true;
  }

 private:
  // The table owns its entries (std::string copies); eviction frees them
  // freely — decode() never lets an `out` view point here.
  [[nodiscard]] bool add_dynamic(std::string_view n, std::string_view v) {
    const std::size_t sz = n.size() + v.size() + 32;
    if (sz > table_max_) {  // §4.4: bigger than the table → empty the table
      dyn_.clear();
      dyn_size_ = 0;
      return true;
    }
    dyn_.emplace_front(std::string(n), std::string(v));
    dyn_size_ += sz;
    while (dyn_size_ > table_max_ && !dyn_.empty()) {
      const auto& b = dyn_.back();
      dyn_size_ -= b.first.size() + b.second.size() + 32;
      dyn_.pop_back();
    }
    return true;
  }

  std::deque<std::pair<std::string, std::string>> dyn_;
  std::size_t dyn_size_ = 0;  // Σ(name + value + 32)
  std::uint32_t table_max_ = 4096;
  std::string huff_scratch_;  // reused per literal — no per-string allocation
};

// ---------------------------------------------------------------------------
// Encoder — stateless (never indexes into a dynamic table).
// ---------------------------------------------------------------------------
class Encoder {
 public:
  void encode(std::string_view name, std::string_view value,
              std::string& out) const {
    for (unsigned i = 0; i < kStaticTableSize; ++i) {
      if (kStaticTable[i].name == name && kStaticTable[i].value == value) {
        encode_uint(out, i + 1, 7, 0x80);  // indexed header field
        return;
      }
    }
    unsigned name_idx = 0;
    for (unsigned i = 0; i < kStaticTableSize; ++i) {
      if (kStaticTable[i].name == name) {
        name_idx = i + 1;
        break;
      }
    }
    if (name_idx)
      encode_uint(out, name_idx, 4, 0x00);  // literal w/o indexing, static name
    else {
      out.push_back('\x00');                 // literal w/o indexing, new name
      encode_string(out, name);
    }
    encode_string(out, value);
  }
};

// ---------------------------------------------------------------------------
inline std::string Decoder::decode(
    std::string_view buf, std::size_t max_headers, std::size_t max_bytes,
    std::vector<Field>& out, Arena& scratch) {
  out.clear();
  std::size_t total = 0;
  bool overflow = false;     // caps exceeded: keep decoding (HPACK state must
                             // stay in sync!) but drop the overflow entries
  bool block_started = false;
  while (!buf.empty()) {
    const std::uint8_t b = std::uint8_t(buf.front());

    const auto fits = [&](std::size_t n, std::size_t v) {
      if (out.size() >= max_headers || total + n + v > max_bytes) {
        overflow = true;
        return false;
      }
      total += n + v;
      return true;
    };

    if ((b & 0x80) != 0) {  // 1xxxxxxx — indexed header field
      std::uint64_t idx = 0;
      if (!decode_uint(buf, 7, idx)) return "compression";
      std::string_view n, v;
      if (!lookup(idx, n, v)) return "compression";
      // Copy through the arena: a later literal insert in this same block
      // could evict the table entry these views point at.
      if (fits(n.size(), v.size()))
        out.emplace_back(scratch.store(n), scratch.store(v));
      block_started = true;
      continue;
    }
    if ((b & 0xc0) == 0x40) {  // 01xxxxxx — literal, incremental indexing
      std::uint64_t idx = 0;
      if (!decode_uint(buf, 6, idx)) return "compression";
      std::string_view n, v;
      if (idx > 0) {
        std::string_view sn, sv;
        if (!lookup(idx, sn, sv)) return "compression";
        n = scratch.store(sn);  // ditto — eviction-safe
        if (!decode_string(buf, scratch, huff_scratch_, v))
          return "compression";
      } else {
        if (!decode_string(buf, scratch, huff_scratch_, n) ||
            !decode_string(buf, scratch, huff_scratch_, v))
          return "compression";
      }
      const bool keep = fits(n.size(), v.size());
      // The insert MUST happen regardless of list overflow, or the peer's
      // dynamic table would drift from ours (→ COMPRESSION_ERROR later).
      (void)add_dynamic(n, v);
      if (keep) out.emplace_back(n, v);
      block_started = true;
      continue;
    }
    if ((b & 0xe0) == 0x20) {  // 001xxxxx — dynamic table size update
      if (block_started) return "compression";  // only before the block
      std::uint64_t m = 0;
      if (!decode_uint(buf, 5, m)) return "compression";
      if (m > table_max_) return "compression";
      table_max_ = std::uint32_t(m);
      while (dyn_size_ > table_max_ && !dyn_.empty()) {
        const auto& e = dyn_.back();
        dyn_size_ -= e.first.size() + e.second.size() + 32;
        dyn_.pop_back();
      }
      continue;
    }
    // 0000xxxx / 0001xxxx — literal without indexing / never indexed
    std::uint64_t idx = 0;
    if (!decode_uint(buf, 4, idx)) return "compression";
    std::string_view n, v;
    if (idx > 0) {
      std::string_view sn, sv;
      if (!lookup(idx, sn, sv)) return "compression";
      n = scratch.store(sn);  // ditto — eviction-safe
      if (!decode_string(buf, scratch, huff_scratch_, v))
        return "compression";
    } else {
      if (!decode_string(buf, scratch, huff_scratch_, n) ||
          !decode_string(buf, scratch, huff_scratch_, v))
        return "compression";
    }
    if (fits(n.size(), v.size())) out.emplace_back(n, v);
    block_started = true;
  }
  return overflow ? "too_large" : "";
}

}  // namespace fw::h2::hpack
