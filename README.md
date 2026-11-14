# fw — modular edition

A C++26 / standalone-Asio web framework (HTTP/1.1 + HTTP/2 + TLS/ALPN + SSE +
the chat demo) — **HTTP/2 implemented from scratch in pure C++26**
(framing, HPACK with Huffman, flow control, multiplexing, GOAWAY — no
nghttp2), split into a proper library/application tree for separation of
concerns. The only protocol dependency is OpenSSL, and only for TLS
(build with `FW_TLS=0` and even that disappears — h2c + HTTP/1.1 are pure).
This tree is the one to develop in.

## Layout

```
fw/                     the reusable protocol library (namespace fw)
├── fw.hpp              umbrella include — apps just include this
├── detail/base.hpp     common includes + build flags (ASIO_STANDALONE, …)
├── util.hpp            clocks/timeouts, logging, string & number helpers,
│                       percent-decoding, random tokens, server_id()
├── json.hpp            strict JSON parser + serializer
├── multipart.hpp       strict RFC 2046 multipart/form-data parser
├── message.hpp         Request / Response, status text, MIME, SSE framing,
│                       target parsing (shared by h1 and h2)
├── limits.hpp          every size cap and clock (enforced pre-allocation)
├── config.hpp          ServerConfig (bind/port/docroot/tls/flags)
├── latch.hpp           one-shot async event
├── out_stream.hpp      OutStream — bounded channel, single drain coroutine,
│                       natural backpressure (the SSE/streaming heart)
├── hooks.hpp           ServerHooks + HttpCtx — the seam that makes handlers
│                       protocol-agnostic (sessions implement, apps consume)
├── router.hpp          ':id<uint32>' typed params, '*rest' tails
├── app.hpp             App — middleware chain, dispatch, docroot-jailed
│                       static serving on a blocking-I/O pool
├── shutdown.hpp        ShutdownTarget/Registry — SIGINT reaches every session
├── h2_frame.hpp        HTTP/2 wire framing (RFC 9113 §4): frame header
│                       parse/build, payload parsers, constants — pure
├── h2_hpack_tables.hpp HPACK static table + canonical Huffman code
│                       (GENERATED from RFC 7541 Appendices A/B — see
│                       scripts/gen_hpack_tables.py; do not hand-edit)
├── h2_hpack.hpp        HPACK codec (RFC 7541): integer/string primitives,
│                       Huffman encode/decode, dynamic table w/ eviction,
│                       bomb-proof decode caps — pure, no asio
├── h2_conn.hpp         the HTTP/2 connection engine: stream state machine,
│                       flow control (conn + per-stream windows), CONTINUATION
│                       reassembly, SETTINGS/PING/GOAWAY, multiplexed DATA —
│                       pure + asio-free, unit-testable headless
├── prefaced_stream.hpp replays sniffed bytes into the TLS handshake (#if FW_TLS)
├── http1_session.hpp    fw::h1 — hardened parser, keep-alive, 100-continue
├── http2_session.hpp   fw::h2 — asio adapter around h2_conn: strand, pump
│                       (single writer), per-stream sendq watermarks, SSE
├── listener.hpp        one port, three protocols: sniff → TLS/h2c/h1
└── sessions.cpp        the only library TU: explicit instantiation of the
                        session templates for the two stream types the
                        Listener creates (plain TCP, TLS-over-PrefacedStream)

app/                    the chat demo application (namespace fw::chat)
├── chat_hub.hpp        shared chat state: two-phase join (atomic name claim
│                       → token → SSE attach), history, private chats, flood control
├── chat_routes.hpp     declares wire()
├── chat_routes.cpp     every chat/upload route
├── selftest.cpp        61 unit tests (json, multipart, router, parsing, hygiene)
├── selftest_h2.cpp     28 HTTP/2 tests: RFC 7541 Appendix C conformance
│                       (Huffman, dynamic-table reuse + eviction), framing,
│                       engine scenarios (PING, flow windows, REFUSED_STREAM,
│                       COMPRESSION_ERROR → GOAWAY)
└── main.cpp            CLI, bootstrap, signals, thread pool

examples/
└── hello.cpp           a SECOND, chat-free app on the same library — proof
                        that app/ ↔ fw/ is a real boundary

public/                 chat UI (sse.html)
third_party/
└── asio/               bundled standalone Asio 1.34.2 headers (used
                        automatically; Boost Software License — see
                        third_party/asio.COPYING). Override with ASIO_ROOT
                        / FW_ASIO_ROOT to use any Asio >= 1.31 instead.
dev_cert.sh             self-signed cert generator (SANs for LAN IPs)
CMakeLists.txt          cmake build (library + app + selftest target)
Makefile                plain make build for cmake-less days
```

Dependency direction is strictly downward: an app includes `fw/fw.hpp`,
nothing in `fw/` ever includes `app/`.

## Build

Requirements: g++ ≥ 14 (or clang ≥ 18), libssl-dev — **only for TLS**.
HTTP/2 is built in (pure C++26), so a bare `make` with no OpenSSL still
yields a full HTTP/1.1 + h2c server. Standalone Asio ≥ 1.31
(`asio/cancel_after.hpp`) is **bundled** in `third_party/asio` — both build
systems pick it up automatically. To use a different/newer Asio, pass
`ASIO_ROOT=...` (Make) or `-DFW_ASIO_ROOT=...` (CMake).

```sh
# with make (uses bundled asio)
make -j
./webfw --selftest

# with cmake (uses bundled asio)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j && ./build/webfw --selftest

# sanitizer build (ASan + UBSan)
make webfw_san && ./webfw_san --selftest
#   or: cmake -DFW_SANITIZE=ON …

# raw g++ (what the Makefile does)
g++ -std=c++26 -O2 -Wall -Wextra -Wpedantic -pthread \
    -DFW_HTTP2=1 -DFW_TLS=1 -Ithird_party/asio -I. \
    fw/sessions.cpp app/main.cpp app/chat_routes.cpp app/selftest.cpp \
    app/selftest_h2.cpp -o webfw -lssl -lcrypto
```

HTTP/2 is the **default**: the pure-C++ engine (framing + HPACK + flow
control + multiplexing) is always compiled in with `FW_HTTP2=1`. OpenSSL is
only needed for TLS and degrades gracefully when missing (h2c + HTTP/1.1
keep working). `FW_HTTP2=OFF` / `FW_TLS=OFF` exist only to opt out.

## Run

```sh
./webfw --port 8443 --docroot public \
        --tls-cert cert.pem --tls-key key.pem    # h2-over-TLS + h2c + h1
./dev_cert.sh 192.168.0.13                       # self-signed cert w/ SANs
curl -k --http2 https://localhost:8443/api/info   # ALPN "h2"
curl --http2-prior-knowledge http://localhost:8443/api/info   # h2c
curl --http1.1 http://localhost:8443/health
```

## Options reference

### Runtime flags (`webfw --help`)

| flag                | default            | meaning                                            |
|---------------------|--------------------|----------------------------------------------------|
| `--port N`          | 8080               | TCP port to listen on                              |
| `--bind ADDR`       | 0.0.0.0            | bind address (`127.0.0.1` = LAN-invisible)         |
| `--docroot DIR`     | ./public           | static file root; missing dir → static serving off |
| `--threads N`       | min(hardware, 8)   | io threads sharing one `io_context`                |
| `--tls-cert FILE`   | —                  | PEM certificate chain; enables TLS + ALPN h2       |
| `--tls-key FILE`    | —                  | PEM private key (cert **and** key, or no TLS)      |
| `--strict-tls`      | off                | refuse plaintext HTTP on the TLS port (default: plaintext is sniffed and served too) |
| `--no-h2c`          | off                | refuse cleartext HTTP/2 prior-knowledge            |
| `--http1-only`      | off                | disable HTTP/2 entirely, even over TLS             |
| `--max-body BYTES`  | 1048576 (1 MiB)    | per-request body cap → 413 (h1) / RST (h2)         |
| `--max-upload N`    | 52428800 (50 MiB)  | `/chat/upload` route cap                           |
| `--verbose`         | off                | debug logging (per-request h1/h2 lines included)   |
| `--selftest`        | —                  | run the 89 unit tests and exit 0/1                 |
| `--help`, `-h`      | —                  | usage text                                         |

One port, three protocols: the first bytes of every connection are sniffed
(TLS handshake `0x16` → TLS/ALPN; h2 preface → h2c; else HTTP/1.1), so
`--tls-cert`/`--tls-key` **add** TLS to the same port rather than needing a
second one. Ctrl-C (SIGINT/SIGTERM) = graceful shutdown: listener stops,
SSE streams close, 5 s deadline, second signal = hard stop.

### CMake configure options

| option                             | default                  | meaning                                        |
|------------------------------------|--------------------------|------------------------------------------------|
| `-DCMAKE_BUILD_TYPE=`              | Release                  | `Debug` / `RelWithDebInfo` / `MinSizeRel` (single-config generators: Ninja, Makefiles — VS ignores it, uses `--config`) |
| `-DFW_HTTP2=ON\|OFF`               | ON                       | built-in pure-C++ HTTP/2 engine (no deps)     |
| `-DFW_TLS=ON\|OFF`                 | ON                       | TLS/ALPN via OpenSSL; auto-OFF if not found    |
| `-DFW_SANITIZE=ON`                 | OFF                      | ASan + UBSan (GCC/Clang only)                  |
| `-DFW_ASIO_ROOT=<dir>`             | bundled `third_party/asio` | use any standalone Asio ≥ 1.31 instead        |
| `-DCMAKE_PREFIX_PATH=<dir>`        | —                        | extra search prefix for OpenSSL (e.g. a vcpkg `installed/<triplet>` tree) |
| `-DCMAKE_TOOLCHAIN_FILE=...`       | —                        | e.g. vcpkg's toolchain (finds deps AND copies runtime DLLs) |
| `-G <generator>`                   | platform default         | `"Ninja"`, `"MinGW Makefiles"`, `"Visual Studio 17 2022"`, … |
| `-DCMAKE_CXX_COMPILER=`            | g++ / cl                 | `clang++` for llvm-mingw/MSYS2-clang builds    |
| `-DCMAKE_EXPORT_COMPILE_COMMANDS`  | ON (this project)        | emits `build/compile_commands.json` for clangd |

MSVC note: you never pass a standard flag — the CMakeLists maps MSVC to
`/std:c++latest` (cl.exe has no `/std:c++26`; all C++23/26 features fw uses
ship in VS 2022 ≥ 17.8) plus `/utf-8`, `/Zc:__cplusplus`,
`/Zc:preprocessor`. Non-MSVC compilers get `-std=c++26`.

### Make variables (no-CMake route)

| variable   | default                                          | meaning                                |
|------------|--------------------------------------------------|----------------------------------------|
| `ASIO_ROOT`| bundled `third_party/asio`                       | path to any Asio ≥ 1.31 include dir    |
| `FW_HTTP2` | 1                                                | 0 → build without HTTP/2               |
| `FW_TLS`   | 1                                                | 0 → build without TLS                  |
| `CXX`      | g++                                              | e.g. `CXX=clang++`                     |
| `CXXFLAGS` | `-std=c++26 -O2 -Wall -Wextra -Wpedantic -pthread` | override for a debug build: `CXXFLAGS="-std=c++26 -O0 -g -Wall -Wextra -pthread"` |
| targets    | `webfw`, `webfw_san`, `selftest`, `clean`        | `selftest` = build + run unit tests    |

### Compile-time limits (`fw/limits.hpp`)

Everything untrusted-input-related is capped **before** allocation. Library
users can pass their own `Limits` via `App::limits`; the demo binary exposes
only the two most common as CLI flags (see above).

| limit                 | value     | effect on violation                        |
|-----------------------|-----------|--------------------------------------------|
| header section        | 32 KiB    | 431 (both protocols)                       |
| header count          | 100       | 431                                        |
| request body          | 1 MiB     | 413 (h1) / RST (h2) — `--max-body`         |
| concurrent h2 streams | 100       | excess streams answered RST REFUSED_STREAM  |
| h2 send buffer        | 256 KiB high-water per stream | drain pauses, resumes on ACK |
| SSE outbox            | 32 frames/chunks in flight per stream | backpressure (slow client doesn't balloon memory) |
| io timeout            | 30 s      | read/write deadline per operation          |
| idle keep-alive       | 75 s      | close idle h1 connection                   |
| h2 idle               | 300 s     | close idle h2 connection                   |
| TLS handshake         | 10 s      | abort stalled handshake                    |
| whole-request deadline| 30 s      | slowloris defense: kill stuck requests     |

## Windows

The sources are portable C++26 — every platform API goes through asio, and
the few POSIX calls are behind feature detection (`FW_HAS_GETIFADDRS`) or
`_WIN32` shims (the logger uses `localtime_s`/`gmtime_s` on Windows,
`localtime_r`/`gmtime_r` elsewhere). No GCC attributes, no POSIX headers
outside `#if !defined(_WIN32)` guards. CMake links `ws2_32` + `mswsock`
automatically.

### Route 1 — WSL2 (the fully-tested route)

Zero changes: identical `make` / `cmake` commands, same `dev_cert.sh`,
same curl checks as above.

### Route 2 — MSYS2, UCRT64 shell (native .exe)

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake \
                   mingw-w64-ucrt-x86_64-ninja \
                   mingw-w64-ucrt-x86_64-openssl   # TLS only — HTTP/2 is built in
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release   # or Debug
cmake --build build -j
./build/webfw.exe --port 8443 --docroot public
```

Debug/Release is chosen at configure time; omit the flag and it defaults to
Release. Sanitizers: use the CLANG64 environment for ASan (`clang`'s
Windows ASan works; MinGW GCC's is experimental) — or just run
`make webfw_san` under WSL2.

### Route 3 — Visual Studio 2022 + vcpkg (MSVC)

```bat
::  once: set VCPKG_DEFAULT_TRIPLET=x64-windows
vcpkg install openssl

cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
::  ^ use --config Debug for a debug build
build\Release\webfw.exe --port 8443 --docroot public
```

Visual Studio is a *multi-config* generator: no `CMAKE_BUILD_TYPE` — you
pick `--config Debug|Release` at build time (both live side by side in
`build\Debug\` and `build\Release\`). The vcpkg toolchain auto-copies the
required DLLs next to the .exe.

### Route 4 — llvm-mingw (clang) + vcpkg C libraries — verified recipe

HTTP/2 needs nothing at all (pure C++ in the tree); only TLS needs a
library. Works because OpenSSL is a **pure C** library with a stable ABI,
so the MSVC-ABI DLLs from vcpkg's `x64-windows` triplet link cleanly into
a GNU-ABI binary built with llvm-mingw clang.

```bat
::  clang++ (llvm-mingw) on PATH; vcpkg has openssl installed (TLS only)
cmake -G "MinGW Makefiles" -S . -B build ^
  -DCMAKE_CXX_COMPILER=clang++ ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_PREFIX_PATH="C:/Users/Mark/Documents/vcpkg/installed/x64-windows"
cmake --build build -j

::  runtime: the .exe needs vcpkg's DLLs on PATH (the prefix-path route
::  does not auto-copy them — only the toolchain-file route does)
set "PATH=C:\Users\Mark\Documents\vcpkg\installed\x64-windows\bin;%PATH%"

.\build\webfw.exe --port 8443 --docroot public --tls-cert cert.pem --tls-key key.pem
```

`FW_HTTP2=ON -DFW_TLS=ON` are the defaults — passing them explicitly (as in
the verified invocation) is fine and simply pins them. This exact recipe
was verified on Windows 10 with llvm-mingw clang 23 + vcpkg: full stack,
HTTP/2 + TLS/ALPN + SSE chat.

### Debug / Release quick reference

| toolchain                    | debug                                   | release                                    |
|------------------------------|-----------------------------------------|--------------------------------------------|
| CMake + Ninja/Makefiles (any OS) | `-DCMAKE_BUILD_TYPE=Debug`          | `-DCMAKE_BUILD_TYPE=Release` (default)     |
| Visual Studio (multi-config) | `cmake --build build --config Debug`   | `cmake --build build --config Release`     |
| plain `make`                 | `make CXXFLAGS="-std=c++26 -O0 -g -Wall -Wextra -pthread"` | `make -j` (default `-O2`) |
| sanitizers                   | `make webfw_san` or `cmake -DFW_SANITIZE=ON` (GCC/Clang) | — |

### Troubleshooting

**`Target "cmTC_..." requires the language dialect "CXX26". But the
current compiler "MSVC" does not support this`** — you hit the old
CMakeLists (or set `CMAKE_CXX_STANDARD` yourself). cl.exe has no
`/std:c++26` flag, so CMake cannot map the standard for MSVC and dies in
the very first internal probe (`find_package(Threads)`). The fix is
already in this tree: MSVC builds use `/std:c++latest` (which contains
all C++23/26 features shipping in VS 2022), plus `/utf-8`,
`/Zc:__cplusplus`, `/Zc:preprocessor`. If you hand-rolled it instead,
replace the `set(CMAKE_CXX_STANDARD 26)` block with:

```cmake
if(MSVC)
  add_compile_options(/std:c++latest /utf-8 /Zc:__cplusplus /Zc:preprocessor)
else()
  set(CMAKE_CXX_STANDARD 26)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
endif()
```

**MSVC generator + `-DCMAKE_BUILD_TYPE=Release` did nothing** — Visual
Studio is multi-config; pick at build time: `cmake --build build
--config Release`.

**TLS missing in the llvm-mingw build** — OpenSSL wasn't found for that
ABI (llvm-mingw has no package manager). Give CMake a prefix that has it
(Route 4's `CMAKE_PREFIX_PATH`); h2c + HTTP/1.1 work regardless. For the
packaged route use MSYS2 CLANG64 / WSL2.

**The .exe starts and dies with a DLL-not-found dialog** — the vcpkg DLLs
aren't on PATH (Route 4's `set "PATH=..."` line), or use the toolchain-file
route (Route 3) which copies them automatically.

`dev_cert.sh` runs as-is in the MSYS2 / Git-Bash shells (if the `ip`
command is missing it just skips the LAN-IP SANs).

## Writing your own app

Copy `examples/hello.cpp`: include `fw/fw.hpp`, declare routes on an `App`,
hand it to a `Listener` with a `ShutdownRegistry`, run `io_context` on N
threads. Adding a chat route touches only `app/chat_routes.cpp`; framework
changes live in `fw/`. The chat demo is a consumer, not a component.

## Build-time tradeoff (measured, 2-core sandbox)

| change                          | single-file | modular (make -j2) |
|---------------------------------|------------:|-------------------:|
| full clean build                |      26 s   |        52 s         |
| edit a chat route (app/)        |      26 s   |        14 s        |
| edit a framework header (fw/)   |      26 s   |        51 s        |

Header-only libraries pay re-parsing per TU; the single file gets a free
"unity build". In exchange you get an app-only iteration loop twice as fast,
per-module testability, dependency-ordered navigation and no monolithic
merge surface. If clean-build time matters most, build the single-file
edition; if the app loop matters, build this one.

## Verified state

* `--selftest`: **89/89** — 61 general (json, multipart, router, parsing,
  hygiene) + 28 HTTP/2 (RFC 7541 Appendix C conformance incl. Huffman and
  dynamic-table eviction, framing, engine scenarios: PING echo, flow-window
  accounting, REFUSED_STREAM, COMPRESSION_ERROR → GOAWAY)
* E2E against **curl's independent nghttp2 client**: h2c GET/POST, 20 KiB
  header forcing CONTINUATION, 4-way multiplexing, SSE-over-h2c with live
  events, client-cancel RST mid-stream, 3 MiB upload *and* download through
  real flow-control windows, `expect: 100-continue` (interim `:status 100`
  verified on the wire), TLS/ALPN h2, 105-stream floods (exactly 5 refused),
  malformed HPACK → GOAWAY(9)
* ASan+UBSan (`make webfw_san`): the entire matrix above runs with zero
  sanitizer reports (it caught three real lifetime bugs during development:
  a Huffman-tree reallocation UAF, a dangling `H2EngineLimits&` temporary,
  and a send-buffer reallocation during in-flight writes — all fixed)
* every `fw/*.hpp` compiles standalone (include hygiene)
* `examples/hello.cpp` builds and serves h1, h2c and SSE-over-h2c
* both CMake configurations (Release and Debug) configured, built and run
* Windows routes: previously user-verified with nghttp2; the pure-C++ engine
  removes the nghttp2 dependency entirely, so Routes 2–4 now need OpenSSL
  only for TLS (compile-ready by audit — same guarded-POSIX code, MSVC
  `/std:c++latest` mapping, ws2_32/mswsock linking)
