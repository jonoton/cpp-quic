---
layout: default
---

[< Previous: Basic Usage](./basic-usage.html) | [🏠 Home](./) | [Next: Performance Metrics >](./performance-metrics.html)
<hr>

# Advanced Usage (Client & Multi-Stream)

`cpp-quic` provides the `QuicClient` class for connecting to servers, and supports multiplexed bidirectional and unidirectional streams over a single connection.

## Using QuicClient

A typical client connects to a server, opens streams, and sends/receives data.

```cpp
#include "cppquic.hpp"
#include <iostream>
#include <string>

int main() {
    cppquic::QuicClient client;

    client.SetStreamDataHandler(
        [](uint64_t stream_id, const std::vector<uint8_t>& data, bool fin) {
            std::string text(data.begin(), data.end());
            std::cout << "Stream " << stream_id << " response: " << text
                      << (fin ? " [FIN]" : "") << std::endl;
        });

    try {
        client.Start();

        if (!client.Connect("127.0.0.1", 4433)) {
            std::cerr << "Handshake failed." << std::endl;
            return 1;
        }

        uint64_t stream_id = client.OpenStream(true);
        client.SendOnStream(stream_id, "Hello QUIC Server!");

        std::cout << "Sent message. Press Enter to exit." << std::endl;
        std::cin.get();

        client.Disconnect();
        client.Stop();
    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
    }

    return 0;
}
```

## Multi-Stream Transfer

One of QUIC's key advantages is multiplexed streams — multiple independent byte streams within a single connection, avoiding head-of-line blocking.

```cpp
// Open multiple bidirectional streams
std::vector<uint64_t> stream_ids;
for (int i = 0; i < 4; ++i) {
    stream_ids.push_back(client.OpenStream(true));
}

// Send data on each stream concurrently
std::vector<uint8_t> chunk(1000, 'A');
for (auto id : stream_ids) {
    client.SendOnStream(id, chunk, false);
}
```

Each stream maintains independent ordering — data on stream A does not block delivery of data on stream B.

## Unidirectional Streams

You can open unidirectional streams for one-way data flow:

```cpp
uint64_t uni_stream = client.OpenStream(false);  // unidirectional
client.SendOnStream(uni_stream, "One-way data", true);
```

## Stream Flow Control

Each stream has a configurable receive window that limits how much data can be buffered before the sender must wait. This prevents memory exhaustion on the receiver:

```cpp
// On the connection (affects new streams)
auto conn = client.GetConnection();
conn->SetRecvWindowSize(131072);  // 128 KB per stream
```

## Stream Lifecycle

Streams transition through the following states:

| State | Description |
|-------|-------------|
| `Open` | Both directions are open for data |
| `HalfClosedLocal` | Local side sent FIN; can still receive |
| `HalfClosedRemote` | Remote side sent FIN; can still send |
| `Closed` | Both directions closed |

## Connection Handshake

QUIC connections are established via a 1-RTT handshake:

1. **Client** sends a `ClientHello` with its source connection ID.
2. **Server** responds with a `ServerHello` containing its own connection ID.
3. **Connection** transitions to `Connected` state.

```cpp
// Connect with a custom timeout (default 5 seconds)
bool ok = client.Connect("server.example.com", 4433, 10000);
```

## Congestion Control

`cpp-quic` supports multiple congestion control algorithms to adjust data transmission rates according to network congestion and packet loss.

The following algorithms are available via the `CongestionControlAlgorithm` enum:
- `CongestionControlAlgorithm::NewReno` (Default): Implements standard QUIC congestion control and packet pacing (RFC 9002).
- `CongestionControlAlgorithm::Cubic`: Implements CUBIC congestion control using a cubic window growth function.
- `CongestionControlAlgorithm::ConstantWindow`: Disables dynamic pacing by maintaining a large fixed congestion window (useful for benchmarks or controlled high-speed networks).

### Setting Congestion Control

You can specify the default congestion control algorithm on `QuicClient` and `QuicServer` before establishing connections:

```cpp
// Configure client to use CUBIC
client.SetCongestionControlAlgorithm(cppquic::CongestionControlAlgorithm::Cubic);

// Configure server to use ConstantWindow
server.SetCongestionControlAlgorithm(cppquic::CongestionControlAlgorithm::ConstantWindow);
```

### Inspecting Congestion Controller State

For debugging or metrics collection, you can query congestion window details from an active connection:

```cpp
auto conn = client.GetConnection();
if (conn) {
    auto* cc = conn->GetCongestionController();
    if (cc) {
        std::cout << "CC Algorithm: " << cc->GetName() << "\n"
                  << "Congestion Window: " << cc->GetCongestionWindow() << " bytes\n"
                  << "Bytes in Flight: " << cc->GetBytesInFlight() << " bytes" << std::endl;
    }
}
```

## Graceful Close

To close a connection gracefully:

```cpp
client.Disconnect();  // Sends CONNECTION_CLOSE frame
```

The server can also close connections, which will be received by the client and trigger state transitions.

<hr>
[< Previous: Basic Usage](./basic-usage.html) | [🏠 Home](./) | [Next: Performance Metrics >](./performance-metrics.html)
