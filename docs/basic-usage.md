---
layout: default
---

[< Previous: Getting Started](./getting-started.html) | [🏠 Home](./) | [Next: Advanced Usage >](./advanced-usage.html)
<hr>

# Basic Usage (Server)

The `QuicServer` class accepts incoming QUIC connections and dispatches stream data to handlers.

## Starting the Server

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
            // Echo back on the same stream
            server.SendOnStream(conn, stream_id, "Echo: " + text, fin);
        });

    try {
        server.Start();
        std::cout << "Server running. Press Enter to stop." << std::endl;
        std::cin.get();
        server.Stop();
    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
    }

    return 0;
}
```

## Dynamic Port Discovery

Bind to port `0` to let the OS assign a port, then discover it:

```cpp
cppquic::QuicServer server(0);
server.Start();

uint16_t port = server.GetLocalPort();
std::cout << "Server listening on port: " << port << std::endl;
```

## Connection Handler

You can register a handler that fires whenever a new QUIC connection is established:

```cpp
server.SetConnectionHandler(
    [](std::shared_ptr<cppquic::QuicConnection> conn) {
        std::cout << "New connection from " << conn->GetPeer().ToString()
                  << " [" << conn->GetLocalConnectionId().ToHex() << "]" << std::endl;
    });
```

## Error Handling

`cpp-quic` splits error handling into two categories:

1. **Synchronous Errors**: Methods like `Start()` throw `std::runtime_error` on failure.
2. **Asynchronous Errors**: Background errors are dispatched via the error handler callback.

```cpp
server.SetErrorHandler([](int error_code, const std::string& message) {
    std::cerr << "Error [" << error_code << "]: " << message << std::endl;
});
```

## Connection Lifecycle Events

Subscribe to connection events using the PubSub broker:

```cpp
cpppubsub::Worker worker;
auto sub = server.GetEventBroker()
    .Subscribe<cppquic::ConnectionEvent>("connection_events");

worker.AddSubscription<cppquic::ConnectionEvent>(
    sub, [](const cppquic::ConnectionEvent& event) {
        if (event.state == cppquic::ConnectionState::Connected) {
            std::cout << "Connected: " << event.peer.ToString() << std::endl;
        } else {
            std::cout << "Closed: " << event.peer.ToString() << std::endl;
        }
    });

worker.Start();
```

## Logging

Configure a global logger callback:

```cpp
cppquic::SetLogger([](cppquic::LogSeverity severity, const std::string& className,
                      const std::string& message) {
    std::string sevStr;
    switch (severity) {
        case cppquic::LogSeverity::Debug: sevStr = "DEBUG"; break;
        case cppquic::LogSeverity::Info:  sevStr = "INFO"; break;
        case cppquic::LogSeverity::Warn:  sevStr = "WARN"; break;
        case cppquic::LogSeverity::Error: sevStr = "ERROR"; break;
    }
    std::cout << "[" << sevStr << "] " << className << ": " << message << std::endl;
});
```

## Server Configuration

### ALPN Configuration
Configure the application-layer protocols supported by the server (default: `{"h3"}`).

```cpp
server.SetAlpnProtos({"h3", "h3-29"});
```

### QUIC Profile Configuration
Apply optimized profile settings for transport parameters, congestion control, datagram limits, and underlying UDP listener profiles.

```cpp
// Apply high-throughput preset to server
server.SetQuicProfile(cppquic::QuicProfile::HighThroughput());

// Inspect active profile parameters
const auto& profile = server.GetQuicProfile();
std::cout << "Max stream data: " << profile.initial_max_stream_data << std::endl;
```

### Idle Timeout
Connections idle longer than the specified duration are automatically closed.

```cpp
server.SetIdleTimeout(std::chrono::seconds(60));  // Default: 60s
```

### Socket Buffer Sizes
Configure the kernel socket receive and send buffers.

```cpp
server.SetRecvBufferSize(262144);  // 256 KB
server.SetSendBufferSize(262144);  // 256 KB
```

<hr>
[< Previous: Getting Started](./getting-started.html) | [🏠 Home](./) | [Next: Advanced Usage >](./advanced-usage.html)
