# fw — modular edition

A C++26 / standalone-Asio web framework (HTTP/1.1 + HTTP/2 + TLS/ALPN + SSE +
the chat demo) — **HTTP/2 implemented from scratch in pure C++26**
(framing, HPACK with Huffman, flow control, multiplexing, GOAWAY — no
nghttp2), split into a proper library/application tree for separation of
concerns. Two libraries are vendored so nothing has to be installed:
standalone Asio 1.34.2 (I/O) and simdjson 5.1.1 (the heavily-optimized
SIMD JSON parser behind `fw::json::parse`). The only system dependency is
OpenSSL, and only for TLS (build with `FW_TLS=0` and even that disappears
— h2c + HTTP/1.1 are pure). The hot paths are allocation-audited: an
arena backs HPACK decode, request metadata is flat + SSO-friendly, and a
counting-probe selftest fails if per-request allocation churn regresses
(see §Threading model and §Memory management). This tree is the one to
develop in.

## Layout

```
fw/                     the reusable protocol library (namespace fw)
├── fw.hpp              umbrella include — apps just include this
├── detail/base.hpp     common includes + build flags (ASIO_STANDALONE, …)
├── util.hpp            clocks/timeouts, logging, string & number helpers,
│                       percent-decoding, random tokens, server_id(),
│                       cached Date header (per-second, thread-local)
├── arena.hpp           Arena — chunked monotonic (bump) allocator with
│                       move-safe chunks and reset-retention; backs HPACK
│                       decode and other short-lived bulk-freed data
├── json.hpp            JSON Value model + serializer (parse is delegated
│                       to the bundled simdjson — see json_parse.cpp)
├── multipart.hpp       strict RFC 2046 multipart/form-data parser
├── message.hpp         Request / Response (flat, SSO-friendly field lists),
│                       status text, MIME, SSE framing, target parsing
│                       (shared by h1 and h2)
├── limits.hpp          every size cap and clock (enforced pre-allocation)
├── config.hpp          ServerConfig + the thread-pool sizing policy
│                       (auto_io_threads / auto_blocking_threads)
├── detail/mem_probe.hpp allocation-counting probe for the self-tests
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
│                       reassembly, SETTINGS/PING/GOAWAY, multiplexed DATA,
│                       arena-backed HPACK decode + O(n) output/sendq
│                       cursors — pure + asio-free, unit-testable headless
├── prefaced_stream.hpp replays sniffed bytes into the TLS handshake (#if FW_TLS)
├── http1_session.hpp    fw::h1 — hardened parser, keep-alive, 100-continue
├── http2_session.hpp   fw::h2 — asio adapter around h2_conn: strand, pump
│                       (single writer), per-stream sendq watermarks, SSE
├── listener.hpp        one port, three protocols: sniff → TLS/h2c/h1
├── json_parse.cpp      library TU: simdjson-backed fw::json::parse() — the
│                       only file that includes the big amalgamated header
└── sessions.cpp        library TU: explicit instantiation of the session
                        templates for the two stream types the
                        Listener creates (plain TCP, TLS-over-PrefacedStream)

app/                    the chat demo application (namespace fw::chat)
├── chat_hub.hpp        shared chat state: two-phase join (atomic name claim
│                       → token → SSE attach), history, private chats, flood control
├── chat_routes.hpp     declares wire()
├── chat_routes.cpp     every chat/upload route
├── selftest.cpp        74 unit tests (json, multipart, router, parsing,
│                       hygiene, arena, Date cache) + the global allocation
│                       probe (operator new hooks — see §Memory management)
├── selftest_h2.cpp     37 HTTP/2 tests: RFC 7541 Appendix C conformance
│                       (Huffman, dynamic-table reuse + eviction), framing,
│                       engine scenarios (PING, flow windows, REFUSED_STREAM,
│                       COMPRESSION_ERROR → GOAWAY), allocation-count
│                       regression, fragmented-consume cursor regression
└── main.cpp            CLI, bootstrap, signals, thread pool

examples/
└── hello.cpp           a SECOND, chat-free app on the same library — proof
                        that app/ ↔ fw/ is a real boundary

public/                 chat UI (sse.html)
third_party/
├── asio/               bundled standalone Asio 1.34.2 headers (used
│                       automatically; Boost Software License — see
│                       third_party/asio.COPYING). Override with ASIO_ROOT
│                       / FW_ASIO_ROOT to use any Asio >= 1.31 instead.
└── simdjson/           bundled simdjson 5.1.1 official single-header build
                        (unmodified upstream artifact; Apache-2.0/MIT
                        dual-licensed — see third_party/simdjson/LICENSE).
                        SIMD JSON parsing with runtime CPU dispatch; used
                        by fw/json_parse.cpp. No vcpkg/apt install needed.
dev_cert.sh             self-signed cert generator (SANs for LAN IPs)
CMakeLists.txt          cmake build (library + app + selftest target)
Makefile                plain make build for cmake-less days
```

Dependency direction is strictly downward: an app includes `fw/fw.hpp`,
nothing in `fw/` ever includes `app/`.

## Build

Requirements: g++ ≥ 14 (or clang ≥ 18), libssl-dev — **only for TLS**.
HTTP/2 is built in (pure C++26) and JSON parsing uses the **bundled**
simdjson, so a bare `make` with no OpenSSL still yields a full
HTTP/1.1 + h2c server. Standalone Asio ≥ 1.31 (`asio/cancel_after.hpp`)
is **bundled** in `third_party/asio`, simdjson 5.1.1 in
`third_party/simdjson` — both build systems pick both up automatically.
To use a different/newer Asio, pass `ASIO_ROOT=...` (Make) or
`-DFW_ASIO_ROOT=...` (CMake).

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
    -DFW_HTTP2=1 -DFW_TLS=1 -Ithird_party/asio -Ithird_party/simdjson/singleheader -I. \
    fw/sessions.cpp fw/json_parse.cpp \
    third_party/simdjson/singleheader/simdjson.cpp \
    app/main.cpp app/chat_routes.cpp app/selftest.cpp \
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
| `--threads N`       | auto: clamp(cores, 2, 16) | io threads sharing one `io_context` |
| `--blocking-threads N` | auto: clamp(cores/4, 2, 8) | blocking pool for file I/O and offloaded handler work (see §Threading model) |
| `--tls-cert FILE`   | —                  | PEM certificate chain; enables TLS + ALPN h2       |
| `--tls-key FILE`    | —                  | PEM private key (cert **and** key, or no TLS)      |
| `--strict-tls`      | off                | refuse plaintext HTTP on the TLS port (default: plaintext is sniffed and served too) |
| `--no-h2c`          | off                | refuse cleartext HTTP/2 prior-knowledge            |
| `--http1-only`      | off                | disable HTTP/2 entirely, even over TLS             |
| `--max-body BYTES`  | 1048576 (1 MiB)    | per-request body cap → 413 (h1) / RST (h2)         |
| `--max-upload N`    | 52428800 (50 MiB)  | `/chat/upload` route cap                           |
| `--verbose`         | off                | debug logging (per-request h1/h2 lines included)   |
| `--selftest`        | —                  | run the 111 unit tests and exit 0/1               |
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

| variable        | default                                      | meaning                                |
|-----------------|----------------------------------------------|----------------------------------------|
| `ASIO_ROOT`     | bundled `third_party/asio`                   | path to any Asio ≥ 1.31 include dir    |
| `SIMDJSON_ROOT` | bundled `third_party/simdjson/singleheader`  | another simdjson single-header dir     |
| `FW_HTTP2`      | 1                                            | 0 → build without HTTP/2               |
| `FW_TLS`        | 1                                            | 0 → build without TLS                  |
| `CXX`           | g++                                          | e.g. `CXX=clang++`                     |
| `CXXFLAGS`      | `-std=c++26 -O2 -Wall -Wextra -Wpedantic -pthread` | override for a debug build: `CXXFLAGS="-std=c++26 -O0 -g -Wall -Wextra -pthread"` |
| targets         | `webfw`, `webfw_san`, `selftest`, `clean`    | `selftest` = build + run unit tests    |

### Compile-time limits (`fw/limits.hpp`)

Everything untrusted-input-related is capped **before** allocation. Library
users can pass their own `Limits` via `App::limits`; the demo binary exposes
only the two most common as CLI flags (see above).

| limit                 | value     | effect on violation                        |
|-----------------------|-----------|--------------------------------------------|
| header section        | 32 KiB    | 431 (both protocols)                       |
| header count          | 100       | 431                                        |
| JSON nesting depth   | 1024      | 400 (simdjson DEFAULT_MAX_DEPTH)           |
| request body          | 1 MiB     | 413 (h1) / RST (h2) — `--max-body`         |
| concurrent h2 streams | 100       | excess streams answered RST REFUSED_STREAM  |
| h2 send buffer        | 256 KiB high-water per stream | drain pauses, resumes on ACK |
| SSE outbox            | 32 frames/chunks in flight per stream | backpressure (slow client doesn't balloon memory) |
| io timeout            | 30 s      | read/write deadline per operation          |
| idle keep-alive       | 75 s      | close idle h1 connection                   |
| h2 idle               | 300 s     | close idle h2 connection                   |
| TLS handshake         | 10 s      | abort stalled handshake                    |
| whole-request deadline| 30 s      | slowloris defense: kill stuck requests     |

## Threading model

Two pools, one rule: **io threads never block.**

| pool            | default (auto)             | runs                                             |
|-----------------|----------------------------|--------------------------------------------------|
| io threads      | `clamp(cores, 2, 16)`      | one shared `io_context`; accept, all sockets, timers, handlers (coroutines) |
| blocking pool   | `clamp(cores/4, 2, 8)`     | static-file reads and anything a handler offloads |

Sizing rationale (`fw/config.hpp`, overridable per boot):

* Socket work is non-blocking and coroutine-based, so io threads beyond
  core count only add cache/mutex traffic — the ceiling is 16, not "all
  cores", because a 2-vCPU container that reports its host's 128 cores
  must not spawn 128 event-loop threads. The floor of 2 keeps accept and
  timers off a single hot thread; `hardware_concurrency()==0` (unknown)
  falls back to 4.
* The blocking pool serves disk I/O and user offloads — disk-bound, not
  CPU-bound — hence `cores/4` clamped to `[2, 8]`.
* Every connection (and thus every h2 stream) is fenced by a strand;
* the engine's invariant "one coroutine writes to the socket" (h2 `pump_`,
  h1 writer) is preserved in both pools' presence.

Static files already run there (`App::blocking_pool()`), and your handlers
can offload their own blocking work the same way:

```cpp
std::string data = co_await asio::co_spawn(
    fw::App::blocking_pool().get_executor(),
    []() -> asio::awaitable<std::string> {
      co_return read_whatever_blocks();     // DB query, disk, subprocess…
    },
    asio::use_awaitable);                   // resumes on the connection strand
```

The pool is sized at first use and frozen (`App::configure_blocking_pool(n)`
must run before that — main.cpp does it during bootstrap). It is a
process-lifetime static *on purpose*: it must outlive the `io_context` so
completions that race with shutdown still drain during static destruction
instead of touching a dead executor.

Startup prints the chosen sizes:

```
[..] pools  : 4 io threads (8 cores detected), 2 blocking-pool threads — --threads/--blocking-threads to override
```

## Memory management

The allocation story is **bounded buffers, arena scratch, flat metadata,
O(n) cursors** — with allocation counts enforced by regression tests.

### Where allocations actually happen now

| path                                     | allocations (measured, `--selftest` prints them) |
|------------------------------------------|--------------------------------------------------|
| request-target + query parse (3 params)  | 4 (one `Fields` vector growth + non-SSO strings) |
| warm h2 request/response cycle, 8-header request | 4–6 steady state: 1 stream map node, 1 sendq slot, amortized output growth |
| h1 response serialization (any header count) | 0 steady state (capacity reused; only larger-than-before bodies grow the buffer) |
| HPACK header decode, any block size      | 0 after the connection's first block (arena bump) |

### The pieces

* **`fw/arena.hpp` — chunked monotonic arena.** HPACK decode and header-block
  assembly bump-allocate from a per-connection arena (4 KiB first chunk);
  decoded fields are handed to the session as `string_view`s — no
  per-string `std::string` copies. `reset()` (per header block) frees all
  chunks but retains one ≤ 16 KiB chunk, so a warm connection decodes
  header blocks with zero heap traffic while pathological blocks still
  release their memory. Chunks are heap blocks owned by `unique_ptr` and
  transferred wholesale on move — arena-stable views survive moves, which
  is the property a stack-embedded `std::pmr::monotonic_buffer_resource`
  does *not* give you (that is why this class exists instead of PMR).
* **Flat field lists, not maps.** `Request` headers/query/params are
  `std::vector<pair<string,string>>` (≤ 100 entries, SSO covers typical
  names/values): one contiguous buffer instead of a red-black node +
  rebalancing per entry, insertion order preserved, `set_*` keeps the old
  "last write wins" duplicate semantics. Same change in `Router::match`.
* **Two O(n²) memmove patterns fixed in the h2 engine.** `out_.erase(0, n)`
  after every write and `sendq.front().erase(0, n)` after every frame each
  moved the whole remaining buffer — ~32 MB of memmove per MB streamed.
  Both are now cursor-based (`consume()` compacts only past 64 KiB, the
  sendq advances `sq_pos` and pops only fully-sent chunks), verified by a
  selftest that drains 200 KiB through a 64 KiB window in odd-sized slices
  that split frames mid-payload and checks the reassembled byte stream is
  intact frames end-to-end.
* **`std::deque` removed from the per-stream hot path.** libstdc++'s deque
  eagerly allocates ~576 B on construction *and on move* — opening a
  stream used to cost 3 avoidable allocations before any payload existed.
  The engine's send queue is now a minimal vector-based ring (allocates
  nothing until a chunk is actually queued), and streams are constructed
  in place (`map::try_emplace`).
* **Response serialization is allocation-free on a warm connection.**
  h1 keeps a per-connection `wbuf_` (clear-keeps-capacity), writes status
  and content-length with `std::to_chars`, appends header lines with inline
  lowercasing and CRLF-stripping (no `sanitize_header_value`/
  `to_lower_ascii` temporaries), and takes the `Date` header from a
  per-second thread-local cache (no `gmtime`+`strftime`+string per
  response). h2 reuses an assign-in-place header store (`hstore_`) whose
  strings keep their capacity across responses.
* **Per-request `make_shared<cancellation_signal>` eliminated** — h1 re-arms
  one signal per connection (requests are strictly sequential); h2 embeds
  the signal in the stream record the session already owns.
* **Everything untrusted is capped before allocation** (see the limits
  table above): header bombs die at 32 KiB/100 fields *during* HPACK
  decode, bodies at the route limit before buffering, h2 send queues at
  the flow-control high-water mark, SSE outboxes at 32 frames.

### The allocation probe (and what it guarantees)

`app/selftest.cpp` installs counting global `operator new`/`delete`
(plain, array, aligned and nothrow overloads — all forwarding to
`malloc`, inert unless a probe is active, one relaxed atomic load each).
The selftests assert the *measured* counts above, so a change that quietly
re-introduces per-header or per-frame allocation churn fails CI instead of
just being slow. The server binary carries the hooks but never activates
them; production behavior is `malloc`-forwarding identical to the
defaults.

Deliberate non-goals: no global allocator replacement in library code, no
PMR types in the public API (move-safety + SSO already cover our sizes),
no buffer pooling across connections (bounded channels + flow control are
the backpressure story; pooling would trade correctness surface for
little gain at these sizes).

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

```sh
# build the example app against the library (TLS optional — drop
# -DFW_TLS=1/-lssl/-lcrypto for an h1+h2c-only binary)
g++ -std=c++26 -O2 -Wall -Wextra -Wpedantic -pthread \
    -DFW_HTTP2=1 -DFW_TLS=1 \
    -Ithird_party/asio -Ithird_party/simdjson/singleheader -I. \
    examples/hello.cpp fw/sessions.cpp fw/json_parse.cpp \
    third_party/simdjson/singleheader/simdjson.cpp \
    -o hello -lssl -lcrypto
./hello --port 8090 --docroot public
```

## Build-time tradeoff (measured, 2-core sandbox)

| change                          | single-file | modular (make -j2) |
|---------------------------------|------------:|-------------------:|
| full clean build                |      17 s   |        73 s         |
| edit a chat route (app/)        |      17 s   |        15 s         |
| edit a framework header (fw/)   |      17 s   |        60 s         |

The modular clean build now includes the vendored simdjson TU (~40 s of
the 73 s; it is **not** rebuilt when you edit fw/ or app/ files). The
single-file edition keeps the old hand-rolled JSON parser, so it compiles
faster but parses slower — that is the trade you are making.
Header-only libraries pay re-parsing per TU; the single file gets a free
"unity build". In exchange you get an app-only iteration loop at least as
fast, per-module testability, dependency-ordered navigation and no
monolithic merge surface. If clean-build time matters most, build the
single-file edition; if the app loop matters, build this one.

## Verified state

* `--selftest`: **111/111** — 74 general (json, multipart, router, parsing,
  hygiene, arena lifetime/stability/retention, cached Date header,
  allocation-count regressions) + 37 HTTP/2 (RFC 7541 Appendix C
  conformance incl. Huffman and dynamic-table eviction, framing, engine
  scenarios: PING echo, flow-window accounting, REFUSED_STREAM,
  COMPRESSION_ERROR → GOAWAY, warm-cycle allocation counts, fragmented
  `consume()` cursor drain). The JSON tests (escapes, surrogate pairs,
  trailing garbage, lone surrogates, single quotes) all run through the
  bundled simdjson backend. `--selftest` also prints the measured
  allocation counts (see §Memory management).
* JSON: parsing is delegated to bundled simdjson 5.1.1 (official upstream
  single-header artifact, unmodified). `fw::json::parse` semantics are
  unchanged — insertion-ordered objects, duplicate keys preserved (find()
  returns the first), all numbers stored as double, strict UTF-8 — and the
  full matrix below was re-run against the simdjson-backed build.
* E2E against **curl's independent nghttp2 client**: h2c GET/POST, 20 KiB
  header forcing CONTINUATION, 4-way multiplexing, SSE-over-h2c with live
  events, client-cancel RST mid-stream, 3 MiB upload *and* download through
  real flow-control windows, `expect: 100-continue` (interim `:status 100`
  verified on the wire), TLS/ALPN h2, 105-stream floods (exactly 5 refused),
  malformed HPACK → GOAWAY(9)
* threading/memory E2E (re-run after the arena/cursor pass, 28 checks):
  h1 keep-alive×3 on one connection, HEAD parity, h2c multiplexed stream
  ids, token-authenticated multipart uploads over h1 *and* h2c, SSE
  welcome/token/send delivery, **8 MiB random-blob downloads with SHA-256
  verification over h1, h2c and h2-over-TLS** (exercises the output-cursor
  and sendq-offset paths past every compaction threshold), plaintext-on-
  TLS-port sniffing, SSE over h2+TLS, graceful SIGTERM shutdown
* full SSE chat-flow suite (raw-socket clients): welcome/token handshake,
  409 duplicates, 400-vs-401 auth split (malformed body vs unknown token),
  token-owner attribution (impersonation rejected), private chat lifecycle
  (request → accept → unique `private_<id>` stream → messages → ended),
  history replay, stale-token rejection, SVG upload blocked from inline
  view, path-traversal attempts never leak files
* ASan+UBSan (`make webfw_san`, now parallel per-TU objects incl. the
  simdjson TU): the entire matrix above plus a dedicated sanitizer battery
  (h1, h2c, h1-over-TLS, h2-over-TLS, SSE, upload, 6 MiB blob ×2
  transports) runs with **zero sanitizer reports**. During development it
  caught four real lifetime bugs: a Huffman-tree reallocation UAF, a
  dangling `H2EngineLimits&` temporary, a send-buffer reallocation during
  in-flight writes, and (this pass) an alloc-dealloc mismatch in the
  probe's nothrow-new coverage — all fixed.
* every `fw/*.hpp` compiles standalone (include hygiene)
* `examples/hello.cpp` builds (see the one-liner above) and serves h1, h2c
  and SSE-over-h2c (route params verified over both protocols)
* both CMake configurations (Release and Debug) configured, built and run
* Windows routes: previously user-verified with nghttp2; the pure-C++ engine
  removes the nghttp2 dependency entirely, and simdjson is bundled (also
  officially supports MSVC 2019+ and MinGW; CMake adds `/bigobj` for MSVC's
  amalgamated TU), so Routes 2–4 now need OpenSSL only for TLS
  (compile-ready by audit — same guarded-POSIX code, MSVC `/std:c++latest`
  mapping, ws2_32/mswsock linking; the new code follows the same rules:
  `fw_localtime/fw_gmtime` shims, `_aligned_malloc`/`_aligned_free` behind
  `_WIN32` in the probe, no new platform APIs)
