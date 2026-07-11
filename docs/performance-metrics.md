---
layout: default
---

[< Previous: Advanced Usage](./advanced-usage.html) | [🏠 Home](./) | [Next: Architecture & Examples >](./architecture-and-examples.html)
<hr>

# Performance Metrics

Both `QuicServer` and `QuicClient` maintain counters for tracking network throughput, stream activity, and retransmissions.

## Fetching Stats

### Server Stats
Aggregate statistics across all active connections:

```cpp
cppquic::QuicStats stats = server.GetStats();
std::cout << "Packets Sent: " << stats.packets_sent << "\n"
          << "Packets Received: " << stats.packets_received << "\n"
          << "Bytes Sent: " << stats.bytes_sent << "\n"
          << "Bytes Received: " << stats.bytes_received << "\n"
          << "Streams Opened: " << stats.streams_opened << "\n"
          << "Streams Closed: " << stats.streams_closed << "\n"
          << "Retransmissions: " << stats.retransmissions << "\n"
          << "Active Connections: " << stats.active_connections << std::endl;
```

### Client Stats
Statistics for the current connection:

```cpp
cppquic::QuicStats stats = client.GetStats();
std::cout << "Packets Sent: " << stats.packets_sent << "\n"
          << "Bytes Sent: " << stats.bytes_sent << "\n"
          << "Retransmissions: " << stats.retransmissions << std::endl;
```

### Per-Connection Stats
You can also query stats on individual connections:

```cpp
auto conn = server.GetConnection(connection_id);
if (conn) {
    auto conn_stats = conn->GetStats();
    // ...
}
```

## Sliding-Window Throughput Tracking

`cpp-quic` includes a `ThroughputTracker` template class that measures send and receive throughput over a 1-second sliding window:

```cpp
#include "cppquic.hpp"

cppquic::ThroughputTracker<cppquic::QuicClient> tracker(client);

// Query real-time throughput (bytes/second)
double send_speed = tracker.GetSendThroughputBytesPerSec();
double recv_speed = tracker.GetRecvThroughputBytesPerSec();
```

The tracker uses low-frequency background polling of stats and has virtually zero performance overhead on the hot path.

## Formatting Helpers

Use `ScaleBytes` and `ScaleBits` to produce human-readable output:

```cpp
auto scaled = cppquic::ScaleBytes(stats.bytes_sent);
std::cout << scaled.value << " " << scaled.unit << std::endl;  // e.g. "12.50 MB"

auto bits = cppquic::ScaleBits(send_speed * 8.0);
std::cout << bits.value << " " << bits.unit << std::endl;  // e.g. "100.00 Mbps"
```

<hr>
[< Previous: Advanced Usage](./advanced-usage.html) | [🏠 Home](./) | [Next: Architecture & Examples >](./architecture-and-examples.html)
