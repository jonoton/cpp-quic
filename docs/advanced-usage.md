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
    // Backpressure: window is full. Yield or integrate with an async event loop.
    std::this_thread::yield();
}
```

To be notified asynchronously when the flow control window opens up (e.g. after receiving `MAX_DATA` or `MAX_STREAM_DATA` updates from the server), you can register a flow control callback:

```cpp
client.SetFlowControlHandler([&]() {
    // Notify your sending thread or resume sending
    std::lock_guard<std::mutex> lock(client_mutex);
    flow_control_cv.notify_all();
});
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

## QUIC Profiles & Performance Tuning

`QuicProfile` encapsulates protocol flow control limits, congestion control algorithms, datagram MTU settings, stream limits, and underlying UDP transport socket profiles (`cppudpnet::UdpProfile`).

### Profile Parameters

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `cc_algorithm` | `CongestionControlAlgorithm` | Congestion control algorithm (`Cubic`, `NewReno`, `ConstantWindow`) | `Cubic` |
| `initial_cwnd` | `size_t` | Initial congestion window size (bytes) | `10 * 1200` (12 KB) |
| `max_cwnd` | `size_t` | Maximum congestion window cap (bytes) | `16 MB` |
| `max_datagram_size` | `size_t` | Maximum datagram payload size (bytes) | `1200` |
| `initial_max_data` | `uint64_t` | Initial connection-level flow control receive window | `1 MB` |
| `initial_max_stream_data` | `uint64_t` | Initial stream-level flow control receive window | `64 KB` |
| `max_streams_bidi` | `uint64_t` | Initial limit on concurrent bidirectional streams | `100` |
| `max_streams_uni` | `uint64_t` | Initial limit on concurrent unidirectional streams | `100` |
| `ack_delay_exponent` | `uint64_t` | Exponent used to decode ACK Delay field | `3` |
| `active_connection_id_limit` | `uint64_t` | Limit on active destination connection IDs | `2` |
| `pacing_burst_packets` | `size_t` | Number of packets to send in a burst before applying pacing delay | `8` |
| `pacing_delay_us` | `uint64_t` | Microseconds of pacing delay applied after each burst | `50` |
| `udp_profile` | `cppudpnet::UdpProfile` | Underneath socket buffer & I/O profile | Default UDP profile |

### Preset Profiles

`cpp-quic` provides factory methods for common networking environments:

1. **`QuicProfile::HighThroughput()`**
   - Ideal for high-speed local networks, bulk file transfers, and benchmarks.
   - Initial CWND: `64 * 1200` (~76.8 KB), Max CWND: `128 MB`, Initial Max Data / Stream Data: `128 MB`.
   - Max Streams: `1000` bidi / `1000` uni.
   - Pacing: Burst `8` packets, delay `50` us.
   - UDP Profile: `cppudpnet::UdpProfile::HighThroughput()`.

2. **`QuicProfile::HighLatency()`**
   - Tuned for long-fat pipes (satellites, WANs, inter-datacenter links with high RTT).
   - Datagram size: `1400` bytes, Initial CWND: `20 * 1400` (28 KB), Max CWND: `32 MB`.
   - Initial Max Data / Stream Data: `64 MB`.
   - Pacing: Burst `8` packets, delay `100` us.
   - UDP Profile: `cppudpnet::UdpProfile::HighLatency()`.

3. **`QuicProfile::LowBandwidth()`**
   - Designed for constrained, low-throughput, or cellular networks.
   - Congestion Control: `NewReno`, Initial CWND: `4 * 1200` (4.8 KB), Max CWND: `2 MB`.
   - Initial Max Data: `2 MB`, Initial Max Stream Data: `1 MB`, Max Streams: `10`.
   - Pacing: Burst `4` packets, delay `150` us.
   - UDP Profile: `cppudpnet::UdpProfile::LowBandwidth()`.

4. **`QuicProfile::ReliableLAN()`**
   - Optimized for low-loss local area networks with high MTU.
   - Datagram size: `1450` bytes, Initial CWND: `16 * 1450` (23.2 KB), Max CWND: `16 MB`.
   - Initial Max Data: `32 MB`, Initial Max Stream Data: `16 MB`.
   - Pacing: Burst `16` packets, delay `20` us.
   - UDP Profile: `cppudpnet::UdpProfile::ReliableLAN()`.

### Applying Profiles

Profiles can be configured on the server, client, or an active connection:

```cpp
// Set profile on server (applies to all future accepted connections)
server.SetQuicProfile(cppquic::QuicProfile::HighThroughput());

// Set profile on client (applies to connections initiated by this client)
client.SetQuicProfile(cppquic::QuicProfile::HighThroughput());

// Apply or update profile dynamically on an active QuicConnection
auto conn = client.GetConnection();
if (conn) {
    conn->ApplyProfile(cppquic::QuicProfile::ReliableLAN());
}
```

### Custom Profiles

You can construct and customize a `QuicProfile` struct manually:

```cpp
cppquic::QuicProfile custom;
custom.cc_algorithm = cppquic::CongestionControlAlgorithm::Cubic;
custom.initial_cwnd = 32 * 1200;
custom.max_cwnd = 64 * 1024 * 1024;
custom.initial_max_data = 64 * 1024 * 1024;
custom.initial_max_stream_data = 16 * 1024 * 1024;
custom.pacing_burst_packets = 16;
custom.pacing_delay_us = 10;

client.SetQuicProfile(custom);
```

## Graceful Close

To close a connection gracefully:

```cpp
client.Disconnect();  // Sends CONNECTION_CLOSE frame
```

The server can also close connections, which will be received by the client and trigger state transitions.

<hr>
[< Previous: Basic Usage](./basic-usage.html) | [🏠 Home](./) | [Next: Performance Metrics >](./performance-metrics.html)
