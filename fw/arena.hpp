// ============================================================================
// fw/arena.hpp — Arena: a chunked monotonic (bump) allocator for short-lived,
// bulk-freed data — the header-block / request-metadata scratch memory.
//
// Design goals, in order:
//   1. Correct lifetimes. Storage is owned by the Arena through
//      unique_ptr<byte[]> chunks; every pointer handed out stays valid until
//      reset() or destruction. reset() frees every chunk except one retained
//      chunk of at most kKeepMaxBytes, so a warm per-connection arena serves
//      typical header blocks with ZERO heap traffic while still releasing
//      the memory of any pathological block.
//   2. Move safety. Chunks are heap blocks owned by unique_ptr and a move
//      transfers them wholesale — pointers handed out before the move stay
//      valid in the moved-to object. That is the property a
//      std::pmr::monotonic_buffer_resource with a stack-embedded initial
//      buffer does NOT have, and the reason this class exists instead of PMR.
//   3. Raw bytes only. Objects placed in an arena are never destroyed by
//      it — fw stores byte ranges (strings) and reads them back as
//      std::string_view. Individual deallocation does not exist; that is
//      the point: one free per chunk instead of one free per header.
//
// Not a general-purpose allocator: sizes are known-small (header blocks are
// capped at Limits::max_header_bytes BEFORE anything is allocated) and
// over-aligned placement is not supported (byte storage only).
// ============================================================================
#pragma once

#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "fw/detail/base.hpp"

namespace fw {

class Arena {
 public:
  static constexpr std::size_t kFirstChunkBytes = 4096;    // typical block fits
  static constexpr std::size_t kKeepMaxBytes = 16 * 1024;  // reset() retention

  Arena() = default;
  ~Arena() = default;
  Arena(const Arena&) = delete;
  Arena& operator=(const Arena&) = delete;

  Arena(Arena&& o) noexcept
      : chunks_(std::move(o.chunks_)), cur_idx_(o.cur_idx_), off_(o.off_) {
    o.cur_idx_ = kNpos;
    o.off_ = 0;
  }

  Arena& operator=(Arena&& o) noexcept {
    if (this != &o) {
      chunks_ = std::move(o.chunks_);
      cur_idx_ = std::exchange(o.cur_idx_, kNpos);
      off_ = std::exchange(o.off_, 0);
    }
    return *this;
  }

  // Allocate `n` bytes. The result is aligned for std::max_align_t at
  // least (chunks come from new[]); `align` may request any smaller or
  // equal power of two and is honored by the bump cursor. Never returns
  // null; bad_alloc propagates from new[].
  void* allocate(std::size_t n, std::size_t align = alignof(std::max_align_t)) {
    if (align > alignof(std::max_align_t))  // byte storage only — see header
      align = alignof(std::max_align_t);
    if (has_cursor()) {
      const std::size_t base = (off_ + align - 1) & ~std::size_t(align - 1);
      const Chunk& c = chunks_[cur_idx_];
      if (base + n <= c.size) {
        off_ = base + n;
        return c.data.get() + base;
      }
    }
    // New chunk: big enough for this request plus worst-case cursor
    // re-alignment inside a max_align-ed block. cur_idx_ (not a pointer)
    // keeps the cursor valid across vector reallocation.
    const std::size_t want =
        n > kFirstChunkBytes ? n + align : kFirstChunkBytes;
    chunks_.push_back(Chunk{});
    Chunk& c = chunks_.back();
    c.data.reset(new std::byte[want]);
    c.size = want;
    cur_idx_ = chunks_.size() - 1;
    off_ = n;
    return c.data.get();
  }

  // Copy a byte range into the arena and hand back a stable view.
  // An empty range yields a valid (non-dangling) empty view.
  std::string_view store(std::string_view s) {
    char* p = static_cast<char*>(allocate(s.size(), 1));
    if (!s.empty()) std::memcpy(p, s.data(), s.size());
    return {p, s.size()};
  }

  // Free everything, but keep the largest chunk of at most kKeepMaxBytes
  // so the next typical block bump-allocates from retained memory. Chunks
  // are never copied or shrunk; the chunk vector itself is re-created with
  // size 1 (its growth memory is released too).
  void reset() {
    std::size_t keep_idx = kNpos, keep_size = 0;
    for (std::size_t i = 0; i < chunks_.size(); ++i) {
      const std::size_t sz = chunks_[i].size;
      if (sz <= kKeepMaxBytes && sz >= keep_size) {
        keep_idx = i;
        keep_size = sz;
      }
    }
    if (keep_idx == kNpos) {
      chunks_.clear();
      chunks_.shrink_to_fit();
      cur_idx_ = kNpos;
      off_ = 0;
      return;
    }
    Chunk kept = std::move(chunks_[keep_idx]);
    chunks_.clear();
    chunks_.shrink_to_fit();
    chunks_.push_back(std::move(kept));
    cur_idx_ = 0;
    off_ = 0;
  }

  // ---- introspection (self-tests + ops logging) ------------------------------
  std::size_t bytes_in_use() const {
    if (chunks_.empty()) return 0;
    std::size_t total = 0;
    for (std::size_t i = 0; i + 1 < chunks_.size(); ++i)
      total += chunks_[i].size;
    return total + off_;
  }
  std::size_t chunk_count() const { return chunks_.size(); }
  std::size_t bytes_retained() const {  // capacity kept across reset()
    return chunks_.empty() ? 0 : chunks_.front().size;
  }

 private:
  struct Chunk {
    std::unique_ptr<std::byte[]> data;  // original new[] pointer — never bent
    std::size_t size = 0;               // usable bytes from data.get()
  };

  static constexpr std::size_t kNpos = static_cast<std::size_t>(-1);

  bool has_cursor() const { return cur_idx_ != kNpos; }

  std::vector<Chunk> chunks_;
  std::size_t cur_idx_ = kNpos;  // bump-cursor chunk INDEX (survives growth)
  std::size_t off_ = 0;         // bump offset inside chunks_[cur_idx_]
};

}  // namespace fw
