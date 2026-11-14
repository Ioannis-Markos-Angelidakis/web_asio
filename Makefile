# ===========================================================================
# fw — quick build for people who don't want CMake today.
#   make -j          → ./webfw        (bundled third_party/asio + simdjson)
#   make selftest    → run the unit self-tests
#   make -j webfw_san → ./webfw_san   (ASan + UBSan build, parallel objects)
#   make clean
#
# Knobs (override on the command line):
#   ASIO_ROOT=/path/to/asio/include   standalone Asio >= 1.31
#                                     (defaults to the bundled copy)
#   SIMDJSON_ROOT=...                 JSON parser backend (defaults bundled)
#   FW_HTTP2=1 FW_TLS=1               feature flags (default: both on)
# ===========================================================================
CXX      ?= g++
CXXFLAGS ?= -std=c++26 -O2 -Wall -Wextra -Wpedantic -pthread
ASIO_ROOT    ?= $(if $(wildcard third_party/asio/asio.hpp),third_party/asio,$(HOME)/.local/asio/include)
SIMDJSON_ROOT ?= third_party/simdjson/singleheader
FW_HTTP2 ?= 1
FW_TLS   ?= 1

DEFS := $(if $(FW_HTTP2),-DFW_HTTP2=1,) $(if $(FW_TLS),-DFW_TLS=1,)
LIBS := -pthread $(if $(FW_TLS),-lssl -lcrypto,)
INCS := -I$(ASIO_ROOT) -I$(SIMDJSON_ROOT) -I.

LIB_SRC  := fw/sessions.cpp fw/json_parse.cpp $(SIMDJSON_ROOT)/simdjson.cpp
APP_SRC  := app/main.cpp app/chat_routes.cpp app/selftest.cpp app/selftest_h2.cpp
LIB_OBJ  := $(LIB_SRC:.cpp=.o)
FW_OBJ   := fw/sessions.o fw/json_parse.o
APP_OBJ  := $(APP_SRC:.cpp=.o)
HDRS     := $(wildcard fw/*.hpp fw/detail/*.hpp app/*.hpp)

webfw: $(APP_OBJ) $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEFS) $(INCS) -c $< -o $@

# every header is a dependency of every fw/app TU (header-only library) —
# but NOT of the bundled simdjson.cpp, which only needs its own .h.
$(FW_OBJ) $(APP_OBJ): $(HDRS)

selftest: webfw
	./webfw --selftest

# ---- one-shot ASan+UBSan build (mirrors CMake's -DFW_SANITIZE=ON) ----------
# Compiled per-TU into build_san/ so `make -j webfw_san` parallelizes — the
# amalgamated simdjson.cpp is big enough that a single-TU build hurts.
SANFLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g
SAN_SRC  := $(LIB_SRC) $(APP_SRC)
SAN_OBJ  := $(patsubst %.cpp,build_san/%.o,$(SAN_SRC))

build_san/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(SANFLAGS) $(DEFS) $(INCS) -c $< -o $@

# fw/app objects depend on all headers; third_party only on its own sources
build_san/fw/%.o build_san/app/%.o: $(HDRS)
build_san/third_party/%.o: $(SIMDJSON_ROOT)/simdjson.h

webfw_san: $(SAN_OBJ)
	$(CXX) $(CXXFLAGS) $(SANFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f webfw webfw_san $(LIB_OBJ) $(APP_OBJ)
	rm -rf build_san

.PHONY: selftest clean
