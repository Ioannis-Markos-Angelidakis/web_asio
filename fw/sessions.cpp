// ===========================================================================
// fw/sessions.cpp — the only translation unit of the fw library.
//
// The session classes are templates on the stream type, but the Listener
// ever only instantiates two stream flavours:
//   * plain TCP sockets (cleartext h1 / h2c)
//   * TLS streams whose next layer is a PrefacedStream (sniffed preface)
// Explicit instantiation here means: (a) the app's translation units never
// pay for compiling the sessions, and (b) using any other stream type is a
// clear link-time error, not an accidental code-size blow-up.
// ===========================================================================
#include "fw/http1_session.hpp"
#include "fw/http2_session.hpp"
#include "fw/prefaced_stream.hpp"

namespace fw {

template class h1::Http1Session<asio::ip::tcp::socket>;
#if FW_TLS
using TlsStream = asio::ssl::stream<PrefacedStream<asio::ip::tcp::socket>>;
template class h1::Http1Session<TlsStream>;
#endif
#if FW_HTTP2
template class h2::Http2Session<asio::ip::tcp::socket>;
#if FW_TLS
template class h2::Http2Session<TlsStream>;
#endif
#endif

}  // namespace fw
