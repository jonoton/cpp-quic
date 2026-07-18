# cpp-quic

`cpp-quic` is a cross-platform, header-only C++17 library that implements the QUIC transport protocol. Built on top of [`cpp-udpnet`](https://github.com/jonoton/cpp-udpnet) for UDP transport, it provides multiplexed streams, reliable delivery, and connection management over UDP.

## Features
- **Header-Only:** Include `cppquic.hpp` in your project.
- **Cross-Platform:** Native support for Windows (`Winsock2`) and POSIX (`poll`).
- **TLS 1.3 Encryption:** Mandatory TLS handshake, ALPN negotiation, transport parameters configuration, and AES-GCM (128/256-bit) packet encryption with AAD and header protection using LibreSSL (default) or OpenSSL.
- **QUIC Protocol:** Connection IDs, multiplexed streams, packet numbering, RFC 9000 compliant ACK ranges (sparse ACKs), and retransmission.
- **Multiplexed Streams:** Multiple bidirectional or unidirectional streams over a single connection.
- **Reliable Delivery:** Packet-level ACK tracking with time-based retransmission.
- **ALPN Negotiation:** Set custom application protocol identifiers (e.g., `"h3"`) on clients and servers.
- **Ordered Byte Streams:** Out-of-order packet reassembly for in-order stream delivery.
- **Stream Flow Control:** Per-stream receive window limits prevent buffer overflow.
- **Congestion Control:** Support for multiple congestion control algorithms (`NewReno` (default), `Cubic`, `ConstantWindow`) to adjust the congestion window and pace transmissions.
- **Connection Lifecycle:** Handshake, idle timeout, keep-alive PING, and graceful CONNECTION_CLOSE.
- **Event-Driven:** Uses `cpp-pubsub` for connection and stream lifecycle events.
- **Built-in Thread Pool:** Leverages `cpp-asyncworker` via `cpp-udpnet` for concurrent processing.
- **Performance Metrics:** Track bytes/packets sent/received, streams, retransmissions, and throughput.
- **Dynamic Port Discovery:** Bind to port `0` for OS-assigned ephemeral ports.

## Integration

```cmake
include(FetchContent)

FetchContent_Declare(
  cppquic
  GIT_REPOSITORY https://github.com/jonoton/cpp-quic.git
  GIT_TAG main
)
FetchContent_MakeAvailable(cppquic)

target_link_libraries(your_target PRIVATE cppquic::cppquic)
```

## Quick Start (Server)

```cpp
#include "cppquic.hpp"
#include <iostream>

int main() {
    cppquic::QuicServer server(4433);

    server.SetStreamDataHandler(
        [&server](std::shared_ptr<cppquic::QuicConnection> conn,
                  uint64_t stream_id, const std::vector<uint8_t>& data, bool fin) {
            std::string text(data.begin(), data.end());
            std::cout << "Stream " << stream_id << ": " << text << std::endl;
            server.SendOnStream(conn, stream_id, "Echo: " + text, fin);
        });

    server.Start();
    std::cout << "QUIC Server running. Press Enter to stop." << std::endl;
    std::cin.get();
    server.Stop();
    return 0;
}
```

## Quick Start (Client)

```cpp
#include "cppquic.hpp"
#include <iostream>

int main() {
    cppquic::QuicClient client;

    client.SetStreamDataHandler(
        [](uint64_t stream_id, const std::vector<uint8_t>& data, bool fin) {
            std::string text(data.begin(), data.end());
            std::cout << "Response: " << text << std::endl;
        });

    client.Start();
    if (client.Connect("127.0.0.1", 4433)) {
        uint64_t stream_id = client.OpenStream(true);
        client.SendOnStream(stream_id, "Hello QUIC!");
        std::cin.get();
        client.Disconnect();
    }
    client.Stop();
    return 0;
}
```

## Documentation

Full documentation is available at [https://jonoton.github.io/cpp-quic/](https://jonoton.github.io/cpp-quic/)

## License

MIT License - see [LICENSE](LICENSE) for details.