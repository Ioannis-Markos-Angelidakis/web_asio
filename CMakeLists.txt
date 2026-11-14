cmake_minimum_required(VERSION 3.25)  # CXX_STANDARD 26 needs CMake >= 3.25
project(fw_web LANGUAGES CXX)

# ---------------------------------------------------------------------------
# fw — C++26 standalone-asio web framework (HTTP/1.1 + HTTP/2 + TLS + SSE)
#   Modular layout:
#     fw/  — reusable protocol library (headers + sessions.cpp)
#     app/ — the chat demo application that consumes the library
#
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j
#
# Options:
#   -DFW_HTTP2=ON|OFF   HTTP/2 via nghttp2          (default ON, auto-off if missing)
#   -DFW_TLS=ON|OFF     TLS/ALPN via OpenSSL        (default ON, auto-off if missing)
#   -DFW_SANITIZE=ON    ASan+UBSan build            (GCC/Clang only)
#   -DFW_ASIO_ROOT=...  path to standalone asio's *include* dir
#                       (default: bundled third_party/asio, else system asio)
#
# Debug / Release:
#   single-config generators (Ninja, Makefiles, MSYS2):
#     cmake -S . -B build -DCMAKE_BUILD_TYPE=Release   # or Debug
#     cmake --build build -j
#   multi-config generators (Visual Studio):
#     cmake -S . -B build
#     cmake --build build --config Release             # or Debug
# ---------------------------------------------------------------------------

if(MSVC)
  # cl.exe has no /std:c++26 flag — CMake would reject CMAKE_CXX_STANDARD 26
  # outright (the FindThreads probe fails first, with the confusing
  # "Target requires the language dialect CXX26" error). MSVC ships its
  # C++23/26 features under /std:c++latest, which is all fw needs.
  #  /utf-8          sources AND execution charset are UTF-8 (log strings
  #                  contain UTF-8 arrows / dashes)
  #  /Zc:__cplusplus make __cplusplus truthful (asio feature detection)
  #  /Zc:preprocessor standard-conforming preprocessor (__has_include etc.)
  add_compile_options(/std:c++latest /utf-8 /Zc:__cplusplus /Zc:preprocessor)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
else()
  set(CMAKE_CXX_STANDARD 26)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Release for single-config generators (Ninja / Makefiles) so a
# plain `cmake -S . -B build` is an optimized build. Multi-config generators
# (Visual Studio, Xcode) ignore CMAKE_BUILD_TYPE and pick per build:
#   cmake --build build --config Debug|Release
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Debug | Release | RelWithDebInfo | MinSizeRel" FORCE)
endif()

option(FW_HTTP2 "HTTP/2 support (nghttp2)" ON)
option(FW_TLS "TLS + ALPN support (OpenSSL)" ON)
option(FW_SANITIZE "Address/Undefined sanitizer build" OFF)

find_package(Threads REQUIRED)

# ---- Asio (standalone, header-only) ---------------------------------------
# Search order: FW_ASIO_ROOT override → bundled third_party/asio → system asio.
if(FW_ASIO_ROOT)
  set(ASIO_INCLUDE_DIR "${FW_ASIO_ROOT}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio/asio.hpp")
  set(ASIO_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio")
else()
  find_path(ASIO_INCLUDE_DIR asio.hpp
            PATH_SUFFIXES include
            DOC "standalone asio include directory")
endif()
if(NOT ASIO_INCLUDE_DIR)
  message(FATAL_ERROR
    "standalone asio not found. Install it (e.g. Debian: libasio-dev) or "
    "pass -DFW_ASIO_ROOT=/path/to/asio/include")
endif()
message(STATUS "asio include: ${ASIO_INCLUDE_DIR}")

add_library(fw_asio INTERFACE)
target_include_directories(fw_asio INTERFACE "${ASIO_INCLUDE_DIR}")
# Force the standalone (non-Boost) flavour even when Boost is installed.
target_compile_definitions(fw_asio INTERFACE ASIO_STANDALONE=1)

# The framework needs asio/cancel_after.hpp (standalone Asio >= 1.31).
if(NOT EXISTS "${ASIO_INCLUDE_DIR}/asio/cancel_after.hpp" AND
   NOT EXISTS "${ASIO_INCLUDE_DIR}/asio/experimental/cancel_after.hpp")
  message(FATAL_ERROR
    "Asio in '${ASIO_INCLUDE_DIR}' is too old: fw needs standalone Asio "
    ">= 1.31 (cancel_after). Download a newer asio (e.g. asio-1-34-2) and "
    "pass -DFW_ASIO_ROOT=/path/to/asio/include")
endif()

# ---- OpenSSL ---------------------------------------------------------------
# (HTTP/2 is built in — pure C++26, no nghttp2. TLS/ALPN is the only
#  external protocol library, via asio::ssl over OpenSSL.)
if(FW_TLS)
  find_package(OpenSSL)
  if(NOT OpenSSL_FOUND)
    message(WARNING "OpenSSL not found — building without TLS")
    set(FW_TLS OFF)
  endif()
endif()

# ---- the fw library ----------------------------------------------------------
# Header-only modules + one TU that explicitly instantiates the session
# templates for the stream types the Listener creates. FW_HTTP2 / FW_TLS are
# PUBLIC because the headers themselves are guarded by them.
add_library(fw STATIC fw/sessions.cpp)
target_include_directories(fw PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fw PUBLIC fw_asio Threads::Threads)
if(WIN32)
  # standalone asio needs Winsock (+ mswsock for AcceptEx/ConnectEx);
  # neither MSVC nor MinGW auto-link them.
  target_link_libraries(fw PUBLIC ws2_32 mswsock)
endif()

if(FW_HTTP2)
  target_compile_definitions(fw PUBLIC FW_HTTP2=1)  # built-in pure-c++ h2
endif()

if(FW_TLS)
  target_compile_definitions(fw PUBLIC FW_TLS=1)
  target_link_libraries(fw PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(fw PUBLIC -Wall -Wextra -Wpedantic)
endif()

# ---- the application ---------------------------------------------------------
add_executable(webfw
  app/main.cpp
  app/chat_routes.cpp
  app/selftest.cpp app/selftest_h2.cpp)
target_link_libraries(webfw PRIVATE fw)

if(FW_SANITIZE AND (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
  foreach(tgt fw webfw)
    target_compile_options(${tgt} PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()

# ---- quick test ---------------------------------------------------------------
add_custom_target(fw_selftest
  COMMAND webfw --selftest
  DEPENDS webfw
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "running framework self-tests")
