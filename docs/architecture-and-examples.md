---
layout: default
---

[< Previous: Performance Metrics](./performance-metrics.html) | [🏠 Home](./)
<hr>

# Architecture & Examples

`cpp-quic` is designed as a layered protocol implementation, with the QUIC layer sitting cleanly on top of `cpp-udpnet`'s UDP transport.

## Protocol Stack

```
┌─────────────────────────────────────────┐
│        Application (Your Code)          │
├─────────────────────────────────────────┤
│      QuicServer / QuicClient            │
│  (Connection mgmt, stream dispatch)     │
├─────────────────────────────────────────┤
│         QuicConnection                  │
│  (Handshake, ACKs, retransmission,      │
│   packet numbers, stream mux)           │
├─────────────────────────────────────────┤
│           QuicStream                    │
│  (Ordered byte-stream, flow control,    │
│   FIN handling, reassembly)             │
├─────────────────────────────────────────┤
│  QuicPacket (Serialization/Deser)       │
├─────────────────────────────────────────┤
│     cpp-udpnet (UdpListener/Sender)     │
│  (UDP transport, socket mgmt, polling)  │
├─────────────────────────────────────────┤
│          OS UDP Sockets                 │
└─────────────────────────────────────────┘
```

## Threading Model & Event Loop

`cpp-quic` is built around an event-driven architecture powered by `cpp-pubsub` and `cpp-asyncworker` to maximize performance and avoid blocking:

1. **I/O Polling Loop** (via `cpp-udpnet`): A background thread polls the UDP socket, reads incoming packets, processes the QUIC protocol layer, and publishes events (e.g., connection events, stream data events) to an internal event broker.
2. **Event Worker Thread** (via `cpp-pubsub`): A background thread monitors the event broker, dispatches events to subscribers, and drives the protocol's maintenance ticks (running every 10ms to handle packet retransmissions, pacing, idle timeouts, and connection cleanup).
3. **Asynchronous Callback Dispatch** (via `cpp-asyncworker`): Application-level callbacks (such as the connection handler, stream data handler, and flow control handler) are enqueued to an internal thread pool. This ensures that user code does not block the time-critical I/O or protocol maintenance loops.

> [!WARNING]
> Because application callbacks run asynchronously on thread pool threads, your callback code must be thread-safe when accessing shared application state.

### Packet Pipeline

When a datagram arrives at the server:

1. `UdpListener` receives the raw bytes from the UDP socket.
2. The QUIC layer deserializes the bytes into a `QuicPacket`.
3. The packet's connection ID is used to look up the `QuicConnection`.
4. Each frame in the packet is processed:
   - **CRYPTO** → Reassemble crypto fragments in order per encryption level (RFC 9000 §7.4) and feed the data into TLS to drive the handshake.
   - **STREAM** → Deliver data to the target `QuicStream`, send ACK in the corresponding packet number space.
   - **ACK** → Process RFC 9000-compliant ACK ranges (gaps and lengths) and remove acknowledged packets from the retransmission queue.
   - **PING** → Touch connection activity, send ACK
   - **CONNECTION_CLOSE** → Transition connection to Closed
   - **RESET_STREAM** → Reset the target stream
   - **PATH_CHALLENGE** → Respond with a PATH_RESPONSE frame
   - **PATH_RESPONSE** → Validate path and update active path status
   - **STOP_SENDING** → Reset stream and send a RESET_STREAM frame
   - **MAX_DATA** / **MAX_STREAM_DATA** → Update flow control send limits and trigger queued packet generation
   - **HANDSHAKE_DONE** → Confirm client connection handshake completion

## Included Examples

The `examples/` directory contains several complete, buildable programs:

- **`server.cpp`**: Demonstrates setting up a `QuicServer`, accepting connections, handling stream data with echo logic, and subscribing to connection events.
- **`client.cpp`**: Shows how to use `QuicClient` to connect to a server, open a bidirectional stream, and send/receive data.
- **`stream_transfer.cpp`**: Demonstrates multi-stream concurrent data transfer with performance metrics.
- **`throughput.cpp`**: Measures QUIC throughput with detailed metrics including retransmissions, peak/average throughput, and packet counts.

To build the examples, configure CMake from the project root:

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

<hr>
[< Previous: Performance Metrics](./performance-metrics.html) | [🏠 Home](./)
