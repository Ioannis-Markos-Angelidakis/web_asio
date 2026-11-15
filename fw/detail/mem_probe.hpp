// ============================================================================
// fw/detail/mem_probe.hpp — allocation-counting probe for the self-tests.
//
// The webfw binary (server + selftest in one executable, see Makefile)
// installs counting global operator new/delete overloads — defined once in
// app/selftest.cpp — that forward to malloc/free and, ONLY while a probe is
// active, count allocations. Inert for the running server: one relaxed
// atomic load per allocation, no locks, no behavior change.
//
// This header holds the shared counters + the RAII probe guard. Probes are
// sequential (self-tests are single-threaded); nested probes are not
// supported by design.
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>

namespace fw::detail {

inline std::atomic<bool> g_mem_probe_active{false};
inline std::atomic<std::int64_t> g_mem_probe_allocs{0};
inline std::atomic<std::int64_t> g_mem_probe_bytes{0};

// Usage:
//   warmup();                       // let one-time growth settle
//   fw::detail::MemProbe probe;
//   ... operation under test ...
//   probe.allocs() / probe.bytes()  // net allocations / bytes since start
struct MemProbe {
  const std::int64_t a0;
  const std::int64_t b0;

  MemProbe()
      : a0(g_mem_probe_allocs.load(std::memory_order_relaxed)),
        b0(g_mem_probe_bytes.load(std::memory_order_relaxed)) {
    g_mem_probe_active.store(true, std::memory_order_relaxed);
  }
  ~MemProbe() { g_mem_probe_active.store(false, std::memory_order_relaxed); }

  MemProbe(const MemProbe&) = delete;
  MemProbe& operator=(const MemProbe&) = delete;

  std::int64_t allocs() const {
    return g_mem_probe_allocs.load(std::memory_order_relaxed) - a0;
  }
  std::int64_t bytes() const {
    return g_mem_probe_bytes.load(std::memory_order_relaxed) - b0;
  }
};

}  // namespace fw::detail
