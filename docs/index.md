---
layout: default
---

# cpp-quic

`cpp-quic` is a cross-platform, header-only C++ library implementing the QUIC transport protocol. Built on top of `cpp-udpnet` for UDP transport, it provides multiplexed streams, reliable delivery, connection management, and flow control over UDP.

### Key Features
- **Cross-Platform:** Works natively on Windows (`Winsock2`) and Linux/macOS (`POSIX`).
- **TLS 1.3 Encryption:** Mandatory TLS handshake, ALPN negotiation, transport parameters configuration, and AES-GCM (128/256-bit) packet encryption with AAD and header protection using LibreSSL (default) or OpenSSL.
- **QUIC Protocol:** Connection IDs, multiplexed streams, packet numbering, RFC 9000 compliant ACK ranges (sparse ACKs), and retransmission.
- **ALPN Negotiation:** Set custom application protocol identifiers (e.g., `"h3"`) on clients and servers.
- **Multiplexed Streams:** Multiple bidirectional or unidirectional streams over a single connection.
- **Reliable Delivery:** Packet-level ACK tracking with time-based retransmission and loss detection.
- **Ordered Byte Streams:** Out-of-order packet reassembly ensures in-order stream data delivery.
- **Stream Flow Control:** Per-stream receive window limits prevent buffer overflow.
- **Connection Lifecycle:** 1-RTT handshake, idle timeout, keep-alive PING, and graceful CONNECTION_CLOSE.
- **Event-Driven:** Uses `cpp-pubsub` for connection and stream lifecycle events.
- **Built-in Thread Pool:** Leverages `cpp-asyncworker` via `cpp-udpnet` for concurrent datagram processing with peer affinity.
- **Dynamic Port Discovery:** Bind to port `0` and use `GetLocalPort()` to discover OS-assigned ports.
- **Performance Metrics:** Track bytes/packets sent/received, streams opened/closed, retransmissions, and sliding-window throughput.
- **QUIC Profiles:** Pre-configured performance profiles (`HighThroughput`, `HighLatency`, `LowBandwidth`, `ReliableLAN`) for flow control, congestion control, and transport tuning.
- **Robust Error Handling:** Synchronous setup methods throw exceptions; asynchronous errors use callbacks and PubSub events.

### Documentation

| Page | Description |
|------|-------------|
| [Getting Started](./getting-started.html) | Installation & integration guide |
| [Basic Usage](./basic-usage.html) | `QuicServer` — accepting connections & handling streams |
| [Advanced Usage](./advanced-usage.html) | `QuicClient` — connecting, multi-stream, flow control |
| [Performance Metrics](./performance-metrics.html) | Stats tracking & throughput monitoring |
| [Architecture & Examples](./architecture-and-examples.html) | Protocol design, threading model & example programs |
