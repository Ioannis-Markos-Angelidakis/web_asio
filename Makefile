# ===========================================================================
# fw — quick build for people who don't want CMake today.
#   make -j          → ./webfw        (bundled third_party/asio is used if present)
#   make selftest     → run the unit self-tests
#   make webfw_san    → ./webfw_san   (ASan + UBSan build)
#   make clean
#
# Knobs (override on the command line):
#   ASIO_ROOT=/path/to/asio/include   standalone Asio >= 1.31
#                                     (defaults to the bundled copy)
#   FW_HTTP2=1 FW_TLS=1               feature flags (default: both on)
# ===========================================================================
CXX      ?= g++
CXXFLAGS ?= -std=c++26 -O2 -Wall -Wextra -Wpedantic -pthread
ASIO_ROOT ?= $(if $(wildcard third_party/asio/asio.hpp),third_party/asio,$(HOME)/.local/asio/include)
FW_HTTP2 ?= 1
FW_TLS   ?= 1

DEFS := $(if $(FW_HTTP2),-DFW_HTTP2=1,) $(if $(FW_TLS),-DFW_TLS=1,)
LIBS := -pthread $(if $(FW_TLS),-lssl -lcrypto,)
INCS := -I$(ASIO_ROOT) -I.

LIB_SRC  := fw/sessions.cpp
APP_SRC  := app/main.cpp app/chat_routes.cpp app/selftest.cpp app/selftest_h2.cpp
LIB_OBJ  := $(LIB_SRC:.cpp=.o)
APP_OBJ  := $(APP_SRC:.cpp=.o)

webfw: $(APP_OBJ) $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEFS) $(INCS) -c $< -o $@

# every header is a dependency of every TU (header-only library)
$(APP_OBJ) $(LIB_OBJ): $(wildcard fw/*.hpp fw/detail/*.hpp app/*.hpp)

selftest: webfw
	./webfw --selftest

# one-shot ASan+UBSan build (mirrors CMake's -DFW_SANITIZE=ON)
SANFLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g
webfw_san: $(LIB_SRC) $(APP_SRC) $(wildcard fw/*.hpp fw/detail/*.hpp app/*.hpp)
	$(CXX) $(CXXFLAGS) $(SANFLAGS) $(DEFS) $(INCS) $^ -o $@ $(LIBS) $(SANFLAGS)

clean:
	rm -f webfw webfw_san $(LIB_OBJ) $(APP_OBJ)

.PHONY: selftest clean
