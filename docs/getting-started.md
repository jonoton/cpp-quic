---
layout: default
---

[🏠 Home](./) | [Next: Basic Usage >](./basic-usage.html)
<hr>

# Getting Started

To use `cpp-quic`, include the `cppquic.hpp` header in your project. It depends on `cpp-udpnet` (which transitively depends on `cpp-pubsub` and `cpp-asyncworker`).

## Integration

### 1. CMake: `FetchContent` (Recommended)

You can have CMake automatically download and integrate `cpp-quic` and all its dependencies.

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

### 2. Manual Include

Since `cpp-quic` is a header-only library, you can simply copy `cppquic.hpp` into your project. You will also need `cppudpnet.hpp`, `cpppubsub.hpp`, and `cppasyncworker.hpp` from their respective repositories.

## Prerequisites

- **C++17** or later
- **CMake 3.10+** (for CMake-based integration)
- **Platform:** Windows, Linux, or macOS

### Platform-Specific Notes

- **Windows:** The library automatically links against `ws2_32.lib` and `bcrypt.lib`, and initializes Winsock2.
- **Linux/macOS:** Standard POSIX socket APIs are used. No additional libraries are required.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| [cpp-udpnet](https://github.com/jonoton/cpp-udpnet) | UDP transport layer |
| [cpp-pubsub](https://github.com/jonoton/cpp-pubsub) | Event-driven publish/subscribe messaging |
| [cpp-asyncworker](https://github.com/jonoton/cpp-asyncworker) | Thread pool and asynchronous worker management |

All dependencies are automatically fetched by CMake's `FetchContent` when using the recommended integration method.

<hr>
[🏠 Home](./) | [Next: Basic Usage >](./basic-usage.html)
