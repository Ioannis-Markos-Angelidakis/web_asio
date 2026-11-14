// ===========================================================================
// app/chat_routes.hpp — declaration of the route-wiring entry point.
// Definition lives in chat_routes.cpp; main() calls this.
// ===========================================================================
#pragma once

#include "fw/fw.hpp"
#include "app/chat_hub.hpp"

namespace fw::chat {

// Registers every chat/upload route on `app`.
void wire(App& app, ChatHub& hub, const ServerConfig& cfg);

}  // namespace fw::chat
