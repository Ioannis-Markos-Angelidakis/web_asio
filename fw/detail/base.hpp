// ============================================================================
// fw/detail/base.hpp — Common includes + build config shared by every fw header. Kept as one prelude by design: it mirrors asio's own detail/base approach and keeps per-module includes honest.
// Extracted from the single-file release (web_framework.cpp); see README.
// ============================================================================

#pragma once


#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <memory>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <fstream>
#include <filesystem>
#include <format>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

// Force the standalone (non-Boost) Asio flavour, even when Boost is present.
#if !defined(ASIO_STANDALONE)
#  define ASIO_STANDALONE 1
#endif
#include <asio.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#if __has_include(<asio/cancel_after.hpp>)                 // Asio >= 1.32
#  include <asio/cancel_after.hpp>
#elif __has_include(<asio/experimental/cancel_after.hpp>)  // Asio 1.31
#  include <asio/experimental/cancel_after.hpp>
#else
#  error "fw needs standalone Asio >= 1.31 (asio/cancel_after.hpp). \
Upgrade asio or point FW_ASIO_ROOT at a newer include dir \
(e.g. asio-asio-1-34-2/asio/include)."
#endif

// POSIX interface enumeration (startup banner) — guarded, best effort.
#if !defined(_WIN32)
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <ifaddrs.h>
#  define FW_HAS_GETIFADDRS 1
#endif

#ifndef FW_HTTP2
#  define FW_HTTP2 0
#endif
#ifndef FW_TLS
#  define FW_TLS 0
#endif

#if FW_TLS
#  include <asio/ssl.hpp>
#  include <openssl/ssl.h>
#endif
