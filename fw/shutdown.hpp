// ============================================================================
// fw/shutdown.hpp — ShutdownTarget + ShutdownRegistry — SIGINT reaches every live session (h1: close; h2: GOAWAY).
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once

#include "fw/detail/base.hpp"

namespace fw {
class ShutdownTarget {
 public:
  virtual ~ShutdownTarget() = default;
  virtual void initiate_shutdown() = 0;
};

class ShutdownRegistry {
 public:
  void add(const std::shared_ptr<ShutdownTarget>& t) {
    std::lock_guard<std::mutex> lk(m_);
    live_.insert(t);
  }
  void remove(const std::shared_ptr<ShutdownTarget>& t) {
    std::lock_guard<std::mutex> lk(m_);
    live_.erase(t);
  }
  void shutdown_all() {
    std::vector<std::shared_ptr<ShutdownTarget>> targets;
    {
      std::lock_guard<std::mutex> lk(m_);
      targets.assign(live_.begin(), live_.end());
    }
    for (auto& t : targets) t->initiate_shutdown();
  }

 private:
  std::mutex m_;
  std::set<std::shared_ptr<ShutdownTarget>> live_;
};

}  // namespace fw
