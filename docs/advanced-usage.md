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

### ALPN Configuration
You can configure the application-layer protocols offered by the client during the TLS handshake (default: `{"h3"}`).

```cpp
client.SetAlpnProtos({"h3", "h3-29"});
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

## Flow Control

`cpp-quic` supports stream-level and connection-level flow control in both directions to prevent buffer overflow and memory exhaustion.

### Receive Window (Receiver Side)

You can configure the receive window size (the amount of data we are willing to buffer for the peer). For new streams, this is configured on the connection:

```cpp
// On the connection (affects new streams)
auto conn = client.GetConnection();
conn->SetRecvWindowSize(131072);  // 128 KB per stream
```

### Send Limits (Sender Side)

The library automatically respects flow control limits advertised by the peer via incoming `MAX_DATA` and `MAX_STREAM_DATA` frames:
*   **Stream Send Limit**: A stream will buffer/block writes that exceed the stream send offset limit. This limit starts at 64 KB and is updated when a `MAX_STREAM_DATA` frame is received.
*   **Connection Send Limit**: The connection blocks/limits stream writes that would exceed the connection-wide data limit. This limit starts at 1 MB and is updated when a `MAX_DATA` frame is received.

You can inspect the connection-level flow control limits:

```cpp
auto conn = client.GetConnection();
if (conn) {
    uint64_t max_send = conn->GetMaxSendData();
    uint64_t total_sent = conn->GetTotalStreamBytesSent();
    std::cout << "Flow control: " << total_sent << " / " << max_send << " bytes sent." << std::endl;
}
```

### Backpressure Detection (Client Side)

To prevent application code from queuing more stream data than the current stream-level or connection-level flow-control windows allow, `QuicClient` provides a public, non-blocking method `CanSendOnStream(stream_id, bytes)`:

```cpp
// Check if the stream and connection windows can accommodate 1200 bytes
if (client.CanSendOnStream(stream_id, 1200)) {
    client.SendOnStream(stream_id, data);
} else {
    // Backpressure: window is full. Yield or delay sending.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
}
```


## Stream Lifecycle

Streams transition through the following states:

| State | Description |
|-------|-------------|
| `Open` | Both directions are open for data |
| `HalfClosedLocal` | Local side sent FIN; can still receive |
| `HalfClosedRemote` | Remote side sent FIN; can still send |
| `Closed` | Both directions closed |

## Connection Handshake & 0-RTT (Early Data)

QUIC connections are established via a 1-RTT handshake:

1. **Client** sends a `ClientHello` (Initial packet) with its source connection ID.
2. **Server** responds with a `ServerHello` (Handshake packet) containing its own connection ID.
3. **Connection** transitions to `Connected` state.

```cpp
// Connect with a custom timeout (default 5 seconds)
bool ok = client.Connect("server.example.com", 4433, 10000);
```

### 0-RTT (Early Data)

`cpp-quic` supports 0-RTT data, allowing the client to send stream frames before the handshake completes. 0-RTT data is encrypted using keys derived from the server destination Connection ID and sent in 0-RTT packets. 0-RTT packets are coalesced within the initial `ClientHello` datagram.

To send 0-RTT data, open a stream and send data while the client connection is in the `Handshaking` state:

```cpp
// This stream frame goes out immediately in a 0-RTT packet
uint64_t stream_id = client.OpenStream(true);
client.SendOnStream(stream_id, "Early 0-RTT payload");
```

## Connection Migration & Path Validation

`cpp-quic` supports Connection ID Routing and client-initiated Connection Migration, allowing a connection to survive changes in the client's IP address or source port.

### Connection ID Routing

The server routes incoming UDP datagrams to active connections based on the packet's Destination Connection ID (DCID), rather than the client's source IP and port.

### Path Validation

Before a connection migrates to a new path, the client validates the path by sending a `PATH_CHALLENGE` containing 8 random bytes. The server receives the challenge and responds with a `PATH_RESPONSE` containing the same 8 bytes sent to the client's new path. Once the matching response is received, the client updates the connection's active peer address to the new path.

To initiate path validation:

```cpp
auto conn = client.GetConnection();
if (conn) {
    cppudpnet::PeerAddress new_path{"127.0.0.1", 55555};
    conn->InitiatePathValidation(new_path);
}
```

## Stateless Resets

Under RFC 9000 §10.3, if a node receives a packet for an unknown Connection ID (e.g., after a server crash and restart) and the packet is not an Initial packet, it replies with a **Stateless Reset** packet containing random bytes ending with a 16-byte Stateless Reset Token.

`cpp-quic` automatically generates Stateless Resets for unknown connection IDs, and verifies them on the client side to cleanly terminate connections.

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
