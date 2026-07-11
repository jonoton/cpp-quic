#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "cppudpnet.hpp"

namespace cppquic {
constexpr int VERSION_MAJOR = 1;
constexpr int VERSION_MINOR = 0;
constexpr int VERSION_PATCH = 0;

/**
 * @brief Returns the library version as a string.
 * @return A reference to the version string in "MAJOR.MINOR.PATCH" format.
 */
inline const std::string &version() {
  static const std::string version_str = []() {
    return std::to_string(VERSION_MAJOR) + "." + std::to_string(VERSION_MINOR) +
           "." + std::to_string(VERSION_PATCH);
  }();
  return version_str;
}

// ============================================================================
// Logging
// ============================================================================

/**
 * @brief Represents the severity of a log message.
 */
enum class LogSeverity { Debug, Info, Warn, Error };

/**
 * @brief Callback type for custom logging.
 */
using LogCallback =
    std::function<void(LogSeverity severity, const std::string &className,
                       const std::string &message)>;

namespace internal {

inline std::mutex &GetLoggerMutex() {
  static std::mutex mtx;
  return mtx;
}

inline LogCallback &GetLogger() {
  static LogCallback logger = nullptr;
  return logger;
}

inline void Log(LogSeverity severity, const std::string &className,
                const std::string &message) {
  std::lock_guard<std::mutex> lock(GetLoggerMutex());
  auto &logger = GetLogger();
  if (logger) {
    logger(severity, className, message);
  }
}

}  // namespace internal

/**
 * @brief Sets the global logger callback.
 * @param callback The logger callback, or nullptr to clear.
 */
inline void SetLogger(LogCallback callback) {
  std::lock_guard<std::mutex> lock(internal::GetLoggerMutex());
  internal::GetLogger() = std::move(callback);
}

// ============================================================================
// Utility
// ============================================================================

/**
 * @brief A structure representing a scaled numeric value and its unit label.
 */
struct ScaledUnit {
  double value;
  const char *unit;
};

/**
 * @brief Scales a byte count to its most appropriate binary unit.
 */
inline ScaledUnit ScaleBytes(uint64_t bytes) {
  double size = static_cast<double>(bytes);
  const char *units[] = {"B", "KB", "MB", "GB", "TB"};
  int unit_idx = 0;
  while (size >= 1024.0 && unit_idx < 4) {
    size /= 1024.0;
    unit_idx++;
  }
  return {size, units[unit_idx]};
}

/**
 * @brief Scales a bit rate to its most appropriate decimal unit.
 */
inline ScaledUnit ScaleBits(double bits_per_sec) {
  double rate = bits_per_sec;
  const char *units[] = {"bps", "Kbps", "Mbps", "Gbps", "Tbps"};
  int unit_idx = 0;
  while (rate >= 1000.0 && unit_idx < 4) {
    rate /= 1000.0;
    unit_idx++;
  }
  return {rate, units[unit_idx]};
}

// ============================================================================
// Connection ID
// ============================================================================

/**
 * @brief An 8-byte QUIC connection identifier.
 */
struct ConnectionId {
  uint8_t data[8] = {0};

  bool operator==(const ConnectionId &other) const {
    return std::memcmp(data, other.data, 8) == 0;
  }

  bool operator!=(const ConnectionId &other) const { return !(*this == other); }

  bool IsZero() const {
    for (int i = 0; i < 8; ++i) {
      if (data[i] != 0) return false;
    }
    return true;
  }

  std::string ToHex() const {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(16);
    for (int i = 0; i < 8; ++i) {
      result += hex_chars[(data[i] >> 4) & 0x0F];
      result += hex_chars[data[i] & 0x0F];
    }
    return result;
  }

  /**
   * @brief Serializes this ConnectionId into the end of a byte vector.
   */
  void Serialize(std::vector<uint8_t> &buf) const {
    buf.insert(buf.end(), data, data + 8);
  }

  /**
   * @brief Deserializes a ConnectionId from a buffer at the given offset.
   * @return true on success, false if not enough bytes remain.
   */
  static bool Deserialize(const uint8_t *buf, size_t len, size_t &offset,
                          ConnectionId &out) {
    if (offset + 8 > len) return false;
    std::memcpy(out.data, buf + offset, 8);
    offset += 8;
    return true;
  }
};

/**
 * @brief Hash function for ConnectionId.
 */
struct ConnectionIdHash {
  size_t operator()(const ConnectionId &id) const {
    size_t hash = 0;
    for (int i = 0; i < 8; ++i) {
      hash ^= std::hash<uint8_t>{}(id.data[i]) << (i * 4);
    }
    return hash;
  }
};

namespace internal {

inline ConnectionId GenerateConnectionId() {
  static std::mutex mtx;
  static std::random_device rd;
  static std::mt19937_64 gen(rd());
  std::lock_guard<std::mutex> lock(mtx);
  ConnectionId id;
  uint64_t val = gen();
  while (val == 0) {
    val = gen();
  }
  std::memcpy(id.data, &val, 8);
  return id;
}

}  // namespace internal

// ============================================================================
// Stream ID
// ============================================================================

/**
 * @brief QUIC stream types.
 *
 * Stream ID encoding (low 2 bits):
 *   0b00 = Client-Initiated, Bidirectional
 *   0b01 = Server-Initiated, Bidirectional
 *   0b10 = Client-Initiated, Unidirectional
 *   0b11 = Server-Initiated, Unidirectional
 */
enum class StreamType : uint8_t {
  ClientBidi = 0x00,
  ServerBidi = 0x01,
  ClientUni = 0x02,
  ServerUni = 0x03,
};

/**
 * @brief Creates a stream ID from a sequence number and type.
 */
inline uint64_t MakeStreamId(uint64_t sequence, StreamType type) {
  return (sequence << 2) | static_cast<uint64_t>(type);
}

/**
 * @brief Extracts the stream type from a stream ID.
 */
inline StreamType GetStreamType(uint64_t stream_id) {
  return static_cast<StreamType>(stream_id & 0x03);
}

/**
 * @brief Checks if a stream ID was initiated by the client.
 */
inline bool IsClientInitiated(uint64_t stream_id) {
  return (stream_id & 0x01) == 0;
}

/**
 * @brief Checks if a stream is bidirectional.
 */
inline bool IsBidirectional(uint64_t stream_id) {
  return (stream_id & 0x02) == 0;
}

// ============================================================================
// Frame Types
// ============================================================================

/**
 * @brief QUIC frame type identifiers.
 */
enum class FrameType : uint8_t {
  STREAM = 0x08,
  ACK = 0x02,
  HANDSHAKE = 0x06,
  PING = 0x01,
  CONNECTION_CLOSE = 0x1c,
  RESET_STREAM = 0x04,
};

/**
 * @brief A STREAM frame carrying ordered data for a specific stream.
 */
struct StreamFrame {
  uint64_t stream_id = 0;
  uint64_t offset = 0;
  bool fin = false;
  std::vector<uint8_t> data;
};

/**
 * @brief An ACK frame acknowledging receipt of packets.
 */
struct AckFrame {
  uint64_t largest_acknowledged = 0;
  uint64_t ack_delay_us = 0;
  std::vector<uint64_t> acknowledged_packets;
};

/**
 * @brief A HANDSHAKE frame for connection establishment.
 */
struct HandshakeFrame {
  enum class Type : uint8_t { ClientHello = 1, ServerHello = 2 };
  Type type = Type::ClientHello;
  ConnectionId source_connection_id;
  ConnectionId destination_connection_id;
};

/**
 * @brief A PING frame for keep-alive and RTT probing.
 */
struct PingFrame {};

/**
 * @brief A CONNECTION_CLOSE frame for graceful shutdown.
 */
struct ConnectionCloseFrame {
  uint64_t error_code = 0;
  std::string reason;
};

/**
 * @brief A RESET_STREAM frame for abruptly terminating a stream.
 */
struct ResetStreamFrame {
  uint64_t stream_id = 0;
  uint64_t error_code = 0;
  uint64_t final_size = 0;
};

/**
 * @brief A variant type encompassing all QUIC frame types.
 */
using QuicFrame = std::variant<StreamFrame, AckFrame, HandshakeFrame, PingFrame,
                               ConnectionCloseFrame, ResetStreamFrame>;

// ============================================================================
// Serialization Helpers
// ============================================================================

namespace internal {

inline void WriteUint8(std::vector<uint8_t> &buf, uint8_t val) {
  buf.push_back(val);
}

inline void WriteUint16(std::vector<uint8_t> &buf, uint16_t val) {
  buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

inline void WriteUint32(std::vector<uint8_t> &buf, uint32_t val) {
  buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
  buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

inline void WriteUint64(std::vector<uint8_t> &buf, uint64_t val) {
  for (int i = 7; i >= 0; --i) {
    buf.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
  }
}

inline void WriteBytes(std::vector<uint8_t> &buf, const uint8_t *data,
                       size_t len) {
  buf.insert(buf.end(), data, data + len);
}

inline bool ReadUint8(const uint8_t *buf, size_t len, size_t &offset,
                      uint8_t &out) {
  if (offset + 1 > len) return false;
  out = buf[offset++];
  return true;
}

inline bool ReadUint16(const uint8_t *buf, size_t len, size_t &offset,
                       uint16_t &out) {
  if (offset + 2 > len) return false;
  out = static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
  offset += 2;
  return true;
}

inline bool ReadUint32(const uint8_t *buf, size_t len, size_t &offset,
                       uint32_t &out) {
  if (offset + 4 > len) return false;
  out = static_cast<uint32_t>((buf[offset] << 24) | (buf[offset + 1] << 16) |
                              (buf[offset + 2] << 8) | buf[offset + 3]);
  offset += 4;
  return true;
}

inline bool ReadUint64(const uint8_t *buf, size_t len, size_t &offset,
                       uint64_t &out) {
  if (offset + 8 > len) return false;
  out = 0;
  for (int i = 0; i < 8; ++i) {
    out = (out << 8) | buf[offset + i];
  }
  offset += 8;
  return true;
}

// Serialize a single frame into the buffer
inline void SerializeFrame(std::vector<uint8_t> &buf, const QuicFrame &frame) {
  std::visit(
      [&buf](auto &&f) {
        using T = std::decay_t<decltype(f)>;

        if constexpr (std::is_same_v<T, StreamFrame>) {
          WriteUint8(buf, static_cast<uint8_t>(FrameType::STREAM));
          WriteUint64(buf, f.stream_id);
          WriteUint64(buf, f.offset);
          WriteUint8(buf, f.fin ? 1 : 0);
          WriteUint32(buf, static_cast<uint32_t>(f.data.size()));
          WriteBytes(buf, f.data.data(), f.data.size());

        } else if constexpr (std::is_same_v<T, AckFrame>) {
          WriteUint8(buf, static_cast<uint8_t>(FrameType::ACK));
          WriteUint64(buf, f.largest_acknowledged);
          WriteUint64(buf, f.ack_delay_us);
          WriteUint32(buf,
                      static_cast<uint32_t>(f.acknowledged_packets.size()));
          for (auto pkt : f.acknowledged_packets) {
            WriteUint64(buf, pkt);
          }

        } else if constexpr (std::is_same_v<T, HandshakeFrame>) {
          WriteUint8(buf, static_cast<uint8_t>(FrameType::HANDSHAKE));
          WriteUint8(buf, static_cast<uint8_t>(f.type));
          f.source_connection_id.Serialize(buf);
          f.destination_connection_id.Serialize(buf);

        } else if constexpr (std::is_same_v<T, PingFrame>) {
          WriteUint8(buf, static_cast<uint8_t>(FrameType::PING));

        } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
          WriteUint8(buf, static_cast<uint8_t>(FrameType::CONNECTION_CLOSE));
          WriteUint64(buf, f.error_code);
          WriteUint32(buf, static_cast<uint32_t>(f.reason.size()));
          WriteBytes(buf, reinterpret_cast<const uint8_t *>(f.reason.data()),
                     f.reason.size());

        } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
          WriteUint8(buf, static_cast<uint8_t>(FrameType::RESET_STREAM));
          WriteUint64(buf, f.stream_id);
          WriteUint64(buf, f.error_code);
          WriteUint64(buf, f.final_size);
        }
      },
      frame);
}

// Deserialize one frame from the buffer at offset. Returns false on failure.
inline bool DeserializeFrame(const uint8_t *buf, size_t len, size_t &offset,
                             QuicFrame &out) {
  uint8_t frame_type_raw = 0;
  if (!ReadUint8(buf, len, offset, frame_type_raw)) return false;

  auto frame_type = static_cast<FrameType>(frame_type_raw);

  switch (frame_type) {
    case FrameType::STREAM: {
      StreamFrame f;
      if (!ReadUint64(buf, len, offset, f.stream_id)) return false;
      if (!ReadUint64(buf, len, offset, f.offset)) return false;
      uint8_t fin_byte = 0;
      if (!ReadUint8(buf, len, offset, fin_byte)) return false;
      f.fin = (fin_byte != 0);
      uint32_t data_len = 0;
      if (!ReadUint32(buf, len, offset, data_len)) return false;
      if (offset + data_len > len) return false;
      f.data.assign(buf + offset, buf + offset + data_len);
      offset += data_len;
      out = std::move(f);
      return true;
    }
    case FrameType::ACK: {
      AckFrame f;
      if (!ReadUint64(buf, len, offset, f.largest_acknowledged)) return false;
      if (!ReadUint64(buf, len, offset, f.ack_delay_us)) return false;
      uint32_t count = 0;
      if (!ReadUint32(buf, len, offset, count)) return false;
      f.acknowledged_packets.resize(count);
      for (uint32_t i = 0; i < count; ++i) {
        if (!ReadUint64(buf, len, offset, f.acknowledged_packets[i]))
          return false;
      }
      out = std::move(f);
      return true;
    }
    case FrameType::HANDSHAKE: {
      HandshakeFrame f;
      uint8_t hs_type = 0;
      if (!ReadUint8(buf, len, offset, hs_type)) return false;
      f.type = static_cast<HandshakeFrame::Type>(hs_type);
      if (!ConnectionId::Deserialize(buf, len, offset, f.source_connection_id))
        return false;
      if (!ConnectionId::Deserialize(buf, len, offset,
                                     f.destination_connection_id))
        return false;
      out = std::move(f);
      return true;
    }
    case FrameType::PING: {
      out = PingFrame{};
      return true;
    }
    case FrameType::CONNECTION_CLOSE: {
      ConnectionCloseFrame f;
      if (!ReadUint64(buf, len, offset, f.error_code)) return false;
      uint32_t reason_len = 0;
      if (!ReadUint32(buf, len, offset, reason_len)) return false;
      if (offset + reason_len > len) return false;
      f.reason.assign(reinterpret_cast<const char *>(buf + offset), reason_len);
      offset += reason_len;
      out = std::move(f);
      return true;
    }
    case FrameType::RESET_STREAM: {
      ResetStreamFrame f;
      if (!ReadUint64(buf, len, offset, f.stream_id)) return false;
      if (!ReadUint64(buf, len, offset, f.error_code)) return false;
      if (!ReadUint64(buf, len, offset, f.final_size)) return false;
      out = std::move(f);
      return true;
    }
    default:
      return false;  // Unknown frame type
  }
}

}  // namespace internal

// ============================================================================
// QUIC Packet
// ============================================================================

/**
 * @brief A QUIC packet containing a connection ID, packet number, and frames.
 */
struct QuicPacket {
  ConnectionId connection_id;
  uint64_t packet_number = 0;
  std::vector<QuicFrame> frames;

  /**
   * @brief Serializes this packet into a byte buffer.
   */
  std::vector<uint8_t> Serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(256);

    // Magic byte to identify our QUIC-like packets
    internal::WriteUint8(buf, 0x51);  // 'Q' magic byte
    connection_id.Serialize(buf);
    internal::WriteUint64(buf, packet_number);
    internal::WriteUint16(buf, static_cast<uint16_t>(frames.size()));

    for (const auto &frame : frames) {
      internal::SerializeFrame(buf, frame);
    }

    return buf;
  }

  /**
   * @brief Deserializes a packet from a byte buffer.
   * @return true on success, false on malformed data.
   */
  static bool Deserialize(const std::vector<uint8_t> &data, QuicPacket &out) {
    if (data.empty()) return false;
    const uint8_t *buf = data.data();
    size_t len = data.size();
    size_t offset = 0;

    // Check magic byte
    uint8_t magic = 0;
    if (!internal::ReadUint8(buf, len, offset, magic)) return false;
    if (magic != 0x51) return false;

    if (!ConnectionId::Deserialize(buf, len, offset, out.connection_id))
      return false;
    if (!internal::ReadUint64(buf, len, offset, out.packet_number))
      return false;

    uint16_t frame_count = 0;
    if (!internal::ReadUint16(buf, len, offset, frame_count)) return false;

    out.frames.clear();
    out.frames.reserve(frame_count);
    for (uint16_t i = 0; i < frame_count; ++i) {
      QuicFrame frame;
      if (!internal::DeserializeFrame(buf, len, offset, frame)) return false;
      out.frames.push_back(std::move(frame));
    }

    return true;
  }
};

// ============================================================================
// Stream State
// ============================================================================

/**
 * @brief Represents the state of a QUIC stream.
 */
enum class StreamState { Open, HalfClosedLocal, HalfClosedRemote, Closed };

/**
 * @brief A QUIC stream providing ordered byte-stream delivery.
 */
class QuicStream {
 public:
  QuicStream(uint64_t stream_id, uint64_t initial_recv_window = 65536)
      : stream_id_(stream_id),
        recv_window_(initial_recv_window),
        max_recv_offset_(initial_recv_window) {}

  uint64_t GetStreamId() const { return stream_id_; }

  StreamState GetState() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return state_;
  }

  /**
   * @brief Writes data to the send buffer.
   * @param data The data to send.
   * @param fin If true, marks the end of the stream after this data.
   * @return The frames generated for this write.
   */
  std::vector<StreamFrame> Write(const std::vector<uint8_t> &data,
                                 bool fin = false) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (state_ == StreamState::HalfClosedLocal ||
        state_ == StreamState::Closed) {
      return {};
    }

    std::vector<StreamFrame> frames;
    const size_t max_frame_data = 1200;  // Leave room for headers in MTU
    size_t remaining = data.size();
    size_t data_offset = 0;

    while (remaining > 0 || (data.empty() && fin)) {
      StreamFrame frame;
      frame.stream_id = stream_id_;
      frame.offset = send_offset_;

      size_t chunk = std::min(remaining, max_frame_data);
      if (chunk > 0) {
        frame.data.assign(data.begin() + data_offset,
                          data.begin() + data_offset + chunk);
      }
      data_offset += chunk;
      remaining -= chunk;
      send_offset_ += chunk;

      frame.fin = fin && (remaining == 0);
      frames.push_back(std::move(frame));

      if (data.empty() && fin) break;
    }

    if (fin) {
      if (state_ == StreamState::HalfClosedRemote) {
        state_ = StreamState::Closed;
      } else {
        state_ = StreamState::HalfClosedLocal;
      }
    }

    return frames;
  }

  /**
   * @brief Writes string data to the send buffer.
   */
  std::vector<StreamFrame> Write(const std::string &data, bool fin = false) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    return Write(bytes, fin);
  }

  /**
   * @brief Processes a received STREAM frame, buffering data in-order.
   * @return true if new contiguous data became available.
   */
  bool OnStreamFrame(const StreamFrame &frame) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (state_ == StreamState::HalfClosedRemote ||
        state_ == StreamState::Closed) {
      return false;
    }

    if (frame.offset + frame.data.size() > max_recv_offset_) {
      // Flow control violation
      return false;
    }

    // Buffer the frame for ordered reassembly
    recv_buffer_[frame.offset] = frame.data;
    if (frame.fin) {
      fin_received_ = true;
      fin_offset_ = frame.offset + frame.data.size();
    }

    // Attempt to flush contiguous data to the read buffer
    FlushRecvBuffer();
    return true;
  }

  /**
   * @brief Reads available contiguous data from the stream.
   * @param max_bytes Maximum number of bytes to read (0 = unlimited).
   * @return The available data (may be empty if none ready).
   */
  std::vector<uint8_t> Read(size_t max_bytes = 0) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (read_buffer_.empty()) return {};

    size_t to_read = max_bytes > 0 ? std::min(max_bytes, read_buffer_.size())
                                   : read_buffer_.size();

    std::vector<uint8_t> result(read_buffer_.begin(),
                                read_buffer_.begin() + to_read);
    read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + to_read);

    // Extend receive window
    max_recv_offset_ += to_read;

    return result;
  }

  /**
   * @brief Returns the number of bytes available for reading.
   */
  size_t ReadableBytes() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return read_buffer_.size();
  }

  /**
   * @brief Checks if the stream has received the FIN and all data.
   */
  bool IsFinished() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return fin_received_ && recv_buffer_.empty() && recv_offset_ == fin_offset_;
  }

  /**
   * @brief Resets the stream (abrupt termination).
   */
  void Reset(uint64_t error_code) {
    std::lock_guard<std::mutex> lock(mtx_);
    state_ = StreamState::Closed;
    error_code_ = error_code;
  }

  uint64_t GetSendOffset() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return send_offset_;
  }

  uint64_t GetRecvOffset() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return recv_offset_;
  }

  uint64_t GetRecvWindow() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return recv_window_;
  }

 private:
  void FlushRecvBuffer() {
    while (true) {
      auto it = recv_buffer_.find(recv_offset_);
      if (it == recv_buffer_.end()) break;

      read_buffer_.insert(read_buffer_.end(), it->second.begin(),
                          it->second.end());
      recv_offset_ += it->second.size();
      recv_buffer_.erase(it);
    }

    // Check if stream is fully received
    if (fin_received_ && recv_buffer_.empty() && recv_offset_ == fin_offset_) {
      if (state_ == StreamState::HalfClosedLocal) {
        state_ = StreamState::Closed;
      } else {
        state_ = StreamState::HalfClosedRemote;
      }
    }
  }

  uint64_t stream_id_;
  mutable std::mutex mtx_;

  // Send state
  uint64_t send_offset_ = 0;

  // Receive state
  uint64_t recv_offset_ = 0;
  uint64_t recv_window_;
  uint64_t max_recv_offset_;
  std::map<uint64_t, std::vector<uint8_t>> recv_buffer_;  // offset -> data
  std::vector<uint8_t> read_buffer_;                      // contiguous data

  bool fin_received_ = false;
  uint64_t fin_offset_ = 0;

  StreamState state_ = StreamState::Open;
  uint64_t error_code_ = 0;
};

// ============================================================================
// Connection State
// ============================================================================

/**
 * @brief QUIC connection states.
 */
enum class ConnectionState { Idle, Handshaking, Connected, Draining, Closed };

/**
 * @brief Connection lifecycle event.
 */
struct ConnectionEvent {
  ConnectionId connection_id;
  cppudpnet::PeerAddress peer;
  ConnectionState state;
};

/**
 * @brief Stream lifecycle event.
 */
struct StreamEvent {
  ConnectionId connection_id;
  uint64_t stream_id = 0;
  bool opened = true;  // true = opened, false = closed
};

/**
 * @brief Asynchronous error event.
 */
struct ErrorEvent {
  int error_code = 0;
  std::string message;
};

/**
 * @brief QUIC connection statistics.
 */
struct QuicStats {
  uint64_t bytes_sent = 0;
  uint64_t bytes_received = 0;
  uint64_t packets_sent = 0;
  uint64_t packets_received = 0;
  uint64_t streams_opened = 0;
  uint64_t streams_closed = 0;
  uint64_t retransmissions = 0;
  uint64_t active_connections = 0;
};

// ============================================================================
// QUIC Connection
// ============================================================================

/**
 * @brief Represents a single QUIC connection.
 *
 * Manages streams, packet numbers, ACK tracking, and retransmission.
 */
class QuicConnection {
 public:
  QuicConnection(const ConnectionId &local_id, const ConnectionId &remote_id,
                 const cppudpnet::PeerAddress &peer, bool is_server)
      : local_connection_id_(local_id),
        remote_connection_id_(remote_id),
        peer_(peer),
        is_server_(is_server) {}

  ConnectionId GetLocalConnectionId() const { return local_connection_id_; }
  ConnectionId GetRemoteConnectionId() const { return remote_connection_id_; }
  void SetRemoteConnectionId(const ConnectionId &id) {
    std::lock_guard<std::mutex> lock(mtx_);
    remote_connection_id_ = id;
  }
  cppudpnet::PeerAddress GetPeer() const { return peer_; }

  ConnectionState GetState() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return state_;
  }

  void SetState(ConnectionState state) {
    std::lock_guard<std::mutex> lock(mtx_);
    state_ = state;
  }

  /**
   * @brief Gets or creates a stream by ID.
   */
  std::shared_ptr<QuicStream> GetOrCreateStream(uint64_t stream_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = streams_.find(stream_id);
    if (it != streams_.end()) return it->second;

    auto stream = std::make_shared<QuicStream>(stream_id, recv_window_size_);
    streams_[stream_id] = stream;
    total_streams_opened_++;
    return stream;
  }

  /**
   * @brief Gets a stream by ID, or nullptr if it doesn't exist.
   */
  std::shared_ptr<QuicStream> GetStream(uint64_t stream_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = streams_.find(stream_id);
    if (it != streams_.end()) return it->second;
    return nullptr;
  }

  /**
   * @brief Allocates the next stream ID for client or server initiated streams.
   */
  uint64_t AllocateStreamId(bool bidirectional) {
    std::lock_guard<std::mutex> lock(mtx_);
    StreamType type;
    if (is_server_) {
      type = bidirectional ? StreamType::ServerBidi : StreamType::ServerUni;
    } else {
      type = bidirectional ? StreamType::ClientBidi : StreamType::ClientUni;
    }
    uint64_t id = MakeStreamId(next_stream_sequence_++, type);
    return id;
  }

  /**
   * @brief Creates a QUIC packet from frames and assigns a packet number.
   */
  QuicPacket CreatePacket(std::vector<QuicFrame> frames) {
    std::lock_guard<std::mutex> lock(mtx_);
    QuicPacket pkt;
    pkt.connection_id = remote_connection_id_;
    pkt.packet_number = next_packet_number_++;
    pkt.frames = std::move(frames);

    // Track sent packet for retransmission
    SentPacketInfo info;
    info.packet_number = pkt.packet_number;
    info.send_time = std::chrono::steady_clock::now();
    info.frames = pkt.frames;
    sent_packets_[pkt.packet_number] = std::move(info);

    return pkt;
  }

  /**
   * @brief Creates a handshake packet (ClientHello or ServerHello).
   */
  QuicPacket CreateHandshakePacket() {
    HandshakeFrame hs;
    hs.source_connection_id = local_connection_id_;
    hs.destination_connection_id = remote_connection_id_;
    hs.type = is_server_ ? HandshakeFrame::Type::ServerHello
                         : HandshakeFrame::Type::ClientHello;

    std::vector<QuicFrame> frames;
    frames.push_back(std::move(hs));
    return CreatePacket(std::move(frames));
  }

  /**
   * @brief Processes a received ACK frame, removing acknowledged packets.
   * @return The number of newly acknowledged packets.
   */
  size_t ProcessAck(const AckFrame &ack) {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t acked = 0;
    for (auto pkt_num : ack.acknowledged_packets) {
      if (sent_packets_.erase(pkt_num) > 0) {
        acked++;
      }
    }
    return acked;
  }

  /**
   * @brief Records that a packet was received (for ACK generation).
   */
  void RecordReceivedPacket(uint64_t packet_number) {
    std::lock_guard<std::mutex> lock(mtx_);
    received_packets_.push_back(packet_number);
    if (packet_number > largest_received_packet_) {
      largest_received_packet_ = packet_number;
    }
  }

  /**
   * @brief Generates an ACK frame for received packets.
   * @return An AckFrame acknowledging all unacknowledged received packets.
   */
  AckFrame GenerateAck() {
    std::lock_guard<std::mutex> lock(mtx_);
    AckFrame ack;
    ack.largest_acknowledged = largest_received_packet_;
    ack.ack_delay_us = 0;
    ack.acknowledged_packets = received_packets_;
    received_packets_.clear();
    return ack;
  }

  /**
   * @brief Returns packets that are overdue for retransmission.
   * @param timeout Time since send after which a packet is considered lost.
   */
  std::vector<QuicPacket> GetRetransmissions(
      std::chrono::milliseconds timeout = std::chrono::milliseconds(500)) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = std::chrono::steady_clock::now();
    std::vector<QuicPacket> retransmits;

    std::vector<uint64_t> lost_packets;
    for (auto &[pkt_num, info] : sent_packets_) {
      if (now - info.send_time > timeout) {
        lost_packets.push_back(pkt_num);
      }
    }

    for (auto pkt_num : lost_packets) {
      auto it = sent_packets_.find(pkt_num);
      if (it != sent_packets_.end()) {
        // Create a new packet with the same frames
        QuicPacket pkt;
        pkt.connection_id = remote_connection_id_;
        pkt.packet_number = next_packet_number_++;
        pkt.frames = it->second.frames;

        // Track the new packet
        SentPacketInfo new_info;
        new_info.packet_number = pkt.packet_number;
        new_info.send_time = now;
        new_info.frames = pkt.frames;

        // Remove old, add new
        sent_packets_.erase(it);
        sent_packets_[pkt.packet_number] = std::move(new_info);

        retransmits.push_back(std::move(pkt));
        retransmit_count_++;
      }
    }

    return retransmits;
  }

  /**
   * @brief Creates a CONNECTION_CLOSE packet.
   */
  QuicPacket CreateClosePacket(uint64_t error_code = 0,
                               const std::string &reason = "") {
    ConnectionCloseFrame close_frame;
    close_frame.error_code = error_code;
    close_frame.reason = reason;

    std::vector<QuicFrame> frames;
    frames.push_back(std::move(close_frame));
    return CreatePacket(std::move(frames));
  }

  /**
   * @brief Creates a PING packet for keep-alive.
   */
  QuicPacket CreatePingPacket() {
    std::vector<QuicFrame> frames;
    frames.push_back(PingFrame{});
    return CreatePacket(std::move(frames));
  }

  /**
   * @brief Updates the last activity timestamp.
   */
  void Touch() {
    std::lock_guard<std::mutex> lock(mtx_);
    last_activity_ = std::chrono::steady_clock::now();
  }

  /**
   * @brief Checks if the connection has been idle longer than the timeout.
   */
  bool IsIdle(std::chrono::milliseconds timeout) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return std::chrono::steady_clock::now() - last_activity_ > timeout;
  }

  /**
   * @brief Returns statistics for this connection.
   */
  QuicStats GetStats() const {
    std::lock_guard<std::mutex> lock(mtx_);
    QuicStats stats;
    stats.bytes_sent = bytes_sent_;
    stats.bytes_received = bytes_received_;
    stats.packets_sent = packets_sent_;
    stats.packets_received = packets_received_;
    stats.streams_opened = total_streams_opened_;
    stats.streams_closed = total_streams_closed_;
    stats.retransmissions = retransmit_count_;
    return stats;
  }

  void AddBytesSent(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    bytes_sent_ += bytes;
    packets_sent_++;
  }

  void AddBytesReceived(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    bytes_received_ += bytes;
    packets_received_++;
  }

  /**
   * @brief Gets all stream IDs.
   */
  std::vector<uint64_t> GetStreamIds() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<uint64_t> ids;
    ids.reserve(streams_.size());
    for (const auto &[id, _] : streams_) {
      ids.push_back(id);
    }
    return ids;
  }

  /**
   * @brief Sets the per-stream receive window size for new streams.
   */
  void SetRecvWindowSize(uint64_t size) {
    std::lock_guard<std::mutex> lock(mtx_);
    recv_window_size_ = size;
  }

  /**
   * @brief Returns the number of unacknowledged sent packets.
   */
  size_t PendingAcks() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return sent_packets_.size();
  }

  /**
   * @brief Returns next packet number without incrementing.
   */
  uint64_t PeekNextPacketNumber() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return next_packet_number_;
  }

 private:
  struct SentPacketInfo {
    uint64_t packet_number = 0;
    std::chrono::steady_clock::time_point send_time;
    std::vector<QuicFrame> frames;
  };

  ConnectionId local_connection_id_;
  ConnectionId remote_connection_id_;
  cppudpnet::PeerAddress peer_;
  bool is_server_;

  mutable std::mutex mtx_;

  ConnectionState state_ = ConnectionState::Idle;

  // Streams
  std::unordered_map<uint64_t, std::shared_ptr<QuicStream>> streams_;
  uint64_t next_stream_sequence_ = 0;
  uint64_t recv_window_size_ = 65536;

  // Packet numbers
  uint64_t next_packet_number_ = 0;

  // Sent packet tracking for retransmission
  std::map<uint64_t, SentPacketInfo> sent_packets_;

  // Received packet tracking for ACK generation
  std::vector<uint64_t> received_packets_;
  uint64_t largest_received_packet_ = 0;

  // Stats
  uint64_t bytes_sent_ = 0;
  uint64_t bytes_received_ = 0;
  uint64_t packets_sent_ = 0;
  uint64_t packets_received_ = 0;
  uint64_t total_streams_opened_ = 0;
  uint64_t total_streams_closed_ = 0;
  uint64_t retransmit_count_ = 0;

  // Timing
  std::chrono::steady_clock::time_point last_activity_ =
      std::chrono::steady_clock::now();
};

// ============================================================================
// QUIC Server
// ============================================================================

/**
 * @brief A QUIC server that accepts connections on a bound port.
 *
 * Uses `UdpListener` internally for UDP transport.
 */
class QuicServer {
 public:
  /**
   * @brief Constructs a QUIC server bound to the specified port and address.
   * @param port The port to listen on.
   * @param bind_address The address to bind to (default: "0.0.0.0").
   */
  explicit QuicServer(uint16_t port,
                      const std::string &bind_address = "0.0.0.0")
      : listener_(port, bind_address) {}

  /**
   * @brief Sets the handler for new incoming connections.
   */
  void SetConnectionHandler(
      std::function<void(std::shared_ptr<QuicConnection>)> handler) {
    connection_handler_ = std::move(handler);
  }

  /**
   * @brief Sets the handler for incoming stream data.
   */
  void SetStreamDataHandler(
      std::function<void(std::shared_ptr<QuicConnection>, uint64_t stream_id,
                         const std::vector<uint8_t> &data, bool fin)>
          handler) {
    stream_data_handler_ = std::move(handler);
  }

  /**
   * @brief Sets the error handler callback.
   */
  void SetErrorHandler(
      std::function<void(int error_code, const std::string &message)> handler) {
    error_handler_ = std::move(handler);
    listener_.SetErrorHandler(handler);
  }

  /**
   * @brief Starts the QUIC server.
   * @throws std::runtime_error if already started.
   */
  void Start() {
    if (running_.load()) {
      throw std::runtime_error("QuicServer already started");
    }

    listener_.SetDataHandler([this](uint64_t session_id,
                                    const cppudpnet::PeerAddress &peer,
                                    const std::vector<uint8_t> &data) {
      HandleIncomingPacket(peer, data);
    });

    listener_.Start();
    running_.store(true);

    // Start retransmission and idle timeout checking thread
    maintenance_thread_ = std::thread([this]() { MaintenanceLoop(); });

    internal::Log(LogSeverity::Info, "QuicServer", "Started");
  }

  /**
   * @brief Stops the QUIC server.
   */
  void Stop() {
    if (!running_.load()) return;
    running_.store(false);

    if (maintenance_thread_.joinable()) {
      maintenance_thread_.join();
    }

    // Send CONNECTION_CLOSE to all active connections
    {
      std::lock_guard<std::mutex> lock(connections_mtx_);
      for (auto &[id, conn] : connections_) {
        if (conn->GetState() == ConnectionState::Connected) {
          auto close_pkt = conn->CreateClosePacket(0, "Server shutting down");
          auto bytes = close_pkt.Serialize();
          listener_.Send(conn->GetPeer(), bytes);
          conn->SetState(ConnectionState::Closed);
        }
      }
      connections_.clear();
    }

    listener_.Stop();
    internal::Log(LogSeverity::Info, "QuicServer", "Stopped");
  }

  ~QuicServer() { Stop(); }

  QuicServer(const QuicServer &) = delete;
  QuicServer &operator=(const QuicServer &) = delete;

  /**
   * @brief Gets the locally bound port (useful when binding to port 0).
   */
  uint16_t GetLocalPort() const { return listener_.GetLocalPort(); }

  /**
   * @brief Returns the event broker for subscribing to connection/stream
   * events.
   */
  cpppubsub::PubSub &GetEventBroker() { return event_broker_; }

  /**
   * @brief Returns aggregate statistics across all connections.
   */
  QuicStats GetStats() const {
    std::lock_guard<std::mutex> lock(connections_mtx_);
    QuicStats total;
    total.active_connections = connections_.size();
    for (const auto &[id, conn] : connections_) {
      auto cs = conn->GetStats();
      total.bytes_sent += cs.bytes_sent;
      total.bytes_received += cs.bytes_received;
      total.packets_sent += cs.packets_sent;
      total.packets_received += cs.packets_received;
      total.streams_opened += cs.streams_opened;
      total.streams_closed += cs.streams_closed;
      total.retransmissions += cs.retransmissions;
    }
    return total;
  }

  /**
   * @brief Sends data on a stream within a connection.
   */
  void SendOnStream(std::shared_ptr<QuicConnection> conn, uint64_t stream_id,
                    const std::vector<uint8_t> &data, bool fin = false) {
    auto stream = conn->GetOrCreateStream(stream_id);
    auto frames = stream->Write(data, fin);

    std::vector<QuicFrame> quic_frames;
    for (auto &sf : frames) {
      quic_frames.push_back(std::move(sf));
    }

    auto pkt = conn->CreatePacket(std::move(quic_frames));
    auto bytes = pkt.Serialize();
    conn->AddBytesSent(bytes.size());
    listener_.Send(conn->GetPeer(), bytes);
  }

  /**
   * @brief Sends string data on a stream.
   */
  void SendOnStream(std::shared_ptr<QuicConnection> conn, uint64_t stream_id,
                    const std::string &data, bool fin = false) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    SendOnStream(conn, stream_id, bytes, fin);
  }

  /**
   * @brief Sets the idle timeout for connections.
   */
  void SetIdleTimeout(std::chrono::milliseconds timeout) {
    idle_timeout_ = timeout;
  }

  /**
   * @brief Sets the receive buffer size for the underlying UDP socket.
   */
  void SetRecvBufferSize(int size) { listener_.SetRecvBufferSize(size); }

  /**
   * @brief Sets the send buffer size for the underlying UDP socket.
   */
  void SetSendBufferSize(int size) { listener_.SetSendBufferSize(size); }

  /**
   * @brief Gets a connection by its connection ID.
   */
  std::shared_ptr<QuicConnection> GetConnection(const ConnectionId &id) const {
    std::lock_guard<std::mutex> lock(connections_mtx_);
    auto it = connections_.find(id);
    if (it != connections_.end()) return it->second;
    return nullptr;
  }

 private:
  void HandleIncomingPacket(const cppudpnet::PeerAddress &peer,
                            const std::vector<uint8_t> &data) {
    QuicPacket pkt;
    if (!QuicPacket::Deserialize(data, pkt)) {
      internal::Log(LogSeverity::Warn, "QuicServer",
                    "Failed to deserialize packet from " + peer.ToString());
      return;
    }

    // Look up connection by the connection ID in the packet
    std::shared_ptr<QuicConnection> conn;
    {
      std::lock_guard<std::mutex> lock(connections_mtx_);
      // Search by local connection ID (the packet's connection_id is our local
      // ID from the client's perspective)
      for (auto &[id, c] : connections_) {
        if (c->GetLocalConnectionId() == pkt.connection_id ||
            c->GetRemoteConnectionId() == pkt.connection_id) {
          conn = c;
          break;
        }
      }
    }

    // Process frames
    for (const auto &frame : pkt.frames) {
      std::visit(
          [this, &peer, &pkt, &conn](auto &&f) {
            using T = std::decay_t<decltype(f)>;

            if constexpr (std::is_same_v<T, HandshakeFrame>) {
              if (f.type == HandshakeFrame::Type::ClientHello) {
                HandleClientHello(peer, f);
              }
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                conn->AddBytesReceived(f.data.size());
                HandleStreamFrame(conn, f);
              }
            } else if constexpr (std::is_same_v<T, AckFrame>) {
              if (conn) {
                conn->ProcessAck(f);
              }
            } else if constexpr (std::is_same_v<T, PingFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                // Send ACK back
                SendAck(conn);
              }
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
              if (conn) {
                conn->SetState(ConnectionState::Closed);
                RemoveConnection(conn->GetLocalConnectionId());
                event_broker_.Publish<ConnectionEvent>(
                    "connection_events", {conn->GetLocalConnectionId(), peer,
                                          ConnectionState::Closed});
              }
            } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
              if (conn) {
                auto stream = conn->GetStream(f.stream_id);
                if (stream) {
                  stream->Reset(f.error_code);
                }
              }
            }
          },
          frame);
    }
  }

  void HandleClientHello(const cppudpnet::PeerAddress &peer,
                         const HandshakeFrame &hs) {
    auto local_id = internal::GenerateConnectionId();
    auto remote_id = hs.source_connection_id;

    auto conn =
        std::make_shared<QuicConnection>(local_id, remote_id, peer, true);
    conn->SetState(ConnectionState::Handshaking);

    {
      std::lock_guard<std::mutex> lock(connections_mtx_);
      connections_[local_id] = conn;
    }

    // Send ServerHello
    auto server_hello = conn->CreateHandshakePacket();
    auto bytes = server_hello.Serialize();
    conn->AddBytesSent(bytes.size());
    listener_.Send(peer, bytes);

    conn->SetState(ConnectionState::Connected);
    conn->Touch();

    internal::Log(LogSeverity::Info, "QuicServer",
                  "New connection from " + peer.ToString() + " [" +
                      local_id.ToHex() + "]");

    event_broker_.Publish<ConnectionEvent>(
        "connection_events", {local_id, peer, ConnectionState::Connected});

    if (connection_handler_) {
      connection_handler_(conn);
    }
  }

  void HandleStreamFrame(std::shared_ptr<QuicConnection> conn,
                         const StreamFrame &frame) {
    auto stream = conn->GetOrCreateStream(frame.stream_id);
    stream->OnStreamFrame(frame);

    // Send ACK
    SendAck(conn);

    if (stream_data_handler_) {
      stream_data_handler_(conn, frame.stream_id, frame.data, frame.fin);
    }
  }

  void SendAck(std::shared_ptr<QuicConnection> conn) {
    auto ack = conn->GenerateAck();
    std::vector<QuicFrame> frames;
    frames.push_back(std::move(ack));
    auto pkt = conn->CreatePacket(std::move(frames));
    auto bytes = pkt.Serialize();
    conn->AddBytesSent(bytes.size());
    listener_.Send(conn->GetPeer(), bytes);
  }

  void RemoveConnection(const ConnectionId &id) {
    std::lock_guard<std::mutex> lock(connections_mtx_);
    connections_.erase(id);
  }

  void MaintenanceLoop() {
    while (running_.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      std::vector<std::shared_ptr<QuicConnection>> conns;
      {
        std::lock_guard<std::mutex> lock(connections_mtx_);
        for (auto &[id, conn] : connections_) {
          conns.push_back(conn);
        }
      }

      for (auto &conn : conns) {
        if (conn->GetState() != ConnectionState::Connected) continue;

        // Check idle timeout
        if (conn->IsIdle(idle_timeout_)) {
          auto close_pkt = conn->CreateClosePacket(0, "Idle timeout");
          auto bytes = close_pkt.Serialize();
          listener_.Send(conn->GetPeer(), bytes);
          conn->SetState(ConnectionState::Closed);

          internal::Log(LogSeverity::Info, "QuicServer",
                        "Connection idle timeout: " +
                            conn->GetLocalConnectionId().ToHex());

          event_broker_.Publish<ConnectionEvent>(
              "connection_events", {conn->GetLocalConnectionId(),
                                    conn->GetPeer(), ConnectionState::Closed});

          RemoveConnection(conn->GetLocalConnectionId());
          continue;
        }

        // Process retransmissions
        auto retransmits = conn->GetRetransmissions();
        for (auto &pkt : retransmits) {
          auto bytes = pkt.Serialize();
          conn->AddBytesSent(bytes.size());
          listener_.Send(conn->GetPeer(), bytes);
        }
      }
    }
  }

  cppudpnet::UdpListener listener_;
  cpppubsub::PubSub event_broker_;

  std::atomic<bool> running_{false};
  std::thread maintenance_thread_;

  mutable std::mutex connections_mtx_;
  std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>,
                     ConnectionIdHash>
      connections_;

  std::function<void(std::shared_ptr<QuicConnection>)> connection_handler_;
  std::function<void(std::shared_ptr<QuicConnection>, uint64_t,
                     const std::vector<uint8_t> &, bool)>
      stream_data_handler_;
  std::function<void(int, const std::string &)> error_handler_;

  std::chrono::milliseconds idle_timeout_{60000};
};

// ============================================================================
// QUIC Client
// ============================================================================

/**
 * @brief A QUIC client that connects to a server.
 *
 * Uses `UdpSender` internally for UDP transport.
 */
class QuicClient {
 public:
  QuicClient() = default;

  /**
   * @brief Sets the handler for incoming stream data from the server.
   */
  void SetStreamDataHandler(
      std::function<void(uint64_t stream_id, const std::vector<uint8_t> &data,
                         bool fin)>
          handler) {
    stream_data_handler_ = std::move(handler);
  }

  /**
   * @brief Sets the error handler callback.
   */
  void SetErrorHandler(
      std::function<void(int error_code, const std::string &message)> handler) {
    error_handler_ = std::move(handler);
    sender_.SetErrorHandler(handler);
  }

  /**
   * @brief Starts the client's underlying transport.
   * @throws std::runtime_error if already started.
   */
  void Start() {
    if (running_.load()) {
      throw std::runtime_error("QuicClient already started");
    }

    sender_.Bind(0);

    sender_.SetDataHandler([this](const cppudpnet::PeerAddress &peer,
                                  const std::vector<uint8_t> &data) {
      HandleIncomingPacket(peer, data);
    });

    sender_.Start();
    running_.store(true);

    // Start maintenance thread
    maintenance_thread_ = std::thread([this]() { MaintenanceLoop(); });

    internal::Log(LogSeverity::Info, "QuicClient",
                  "Started on port " + std::to_string(sender_.GetLocalPort()));
  }

  /**
   * @brief Stops the client.
   */
  void Stop() {
    if (!running_.load()) return;
    running_.store(false);

    if (maintenance_thread_.joinable()) {
      maintenance_thread_.join();
    }

    // Send close to connection if active
    if (connection_ && connection_->GetState() == ConnectionState::Connected) {
      auto close_pkt =
          connection_->CreateClosePacket(0, "Client shutting down");
      auto bytes = close_pkt.Serialize();
      sender_.Send(server_address_, bytes);
      connection_->SetState(ConnectionState::Closed);
    }

    sender_.Stop();
    connection_.reset();
    internal::Log(LogSeverity::Info, "QuicClient", "Stopped");
  }

  ~QuicClient() { Stop(); }

  QuicClient(const QuicClient &) = delete;
  QuicClient &operator=(const QuicClient &) = delete;

  /**
   * @brief Connects to a QUIC server.
   * @param host The server hostname or IP address.
   * @param port The server port.
   * @param timeout_ms Timeout in milliseconds for the handshake.
   * @return true if the handshake completed successfully.
   */
  bool Connect(const std::string &host, uint16_t port,
               uint32_t timeout_ms = 5000) {
    if (!running_.load()) {
      throw std::runtime_error("QuicClient not started");
    }

    server_address_ = {host, port};
    auto local_id = internal::GenerateConnectionId();
    auto remote_id = ConnectionId{};  // Will be filled by ServerHello

    connection_ = std::make_shared<QuicConnection>(local_id, remote_id,
                                                   server_address_, false);
    connection_->SetState(ConnectionState::Handshaking);

    // Send ClientHello
    HandshakeFrame hs;
    hs.type = HandshakeFrame::Type::ClientHello;
    hs.source_connection_id = local_id;
    hs.destination_connection_id = remote_id;

    std::vector<QuicFrame> frames;
    frames.push_back(std::move(hs));
    auto pkt = connection_->CreatePacket(std::move(frames));
    auto bytes = pkt.Serialize();
    connection_->AddBytesSent(bytes.size());
    sender_.Send(host, port, bytes);

    internal::Log(
        LogSeverity::Info, "QuicClient",
        "Sending ClientHello to " + host + ":" + std::to_string(port));

    // Wait for handshake completion
    auto start = std::chrono::steady_clock::now();
    while (connection_->GetState() == ConnectionState::Handshaking) {
      if (std::chrono::steady_clock::now() - start >
          std::chrono::milliseconds(timeout_ms)) {
        internal::Log(LogSeverity::Error, "QuicClient", "Handshake timed out");
        connection_->SetState(ConnectionState::Closed);
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return connection_->GetState() == ConnectionState::Connected;
  }

  /**
   * @brief Disconnects from the server.
   */
  void Disconnect() {
    if (!connection_ || connection_->GetState() != ConnectionState::Connected) {
      return;
    }

    auto close_pkt = connection_->CreateClosePacket(0, "Client disconnect");
    auto bytes = close_pkt.Serialize();
    connection_->AddBytesSent(bytes.size());
    sender_.Send(server_address_, bytes);
    connection_->SetState(ConnectionState::Closed);

    internal::Log(LogSeverity::Info, "QuicClient", "Disconnected");
  }

  /**
   * @brief Gets or creates a stream on the current connection.
   */
  std::shared_ptr<QuicStream> GetOrCreateStream(uint64_t stream_id) {
    if (!connection_) return nullptr;
    return connection_->GetOrCreateStream(stream_id);
  }

  /**
   * @brief Allocates a new stream ID.
   */
  uint64_t OpenStream(bool bidirectional = true) {
    if (!connection_) {
      throw std::runtime_error("Not connected");
    }
    uint64_t id = connection_->AllocateStreamId(bidirectional);
    connection_->GetOrCreateStream(id);
    return id;
  }

  /**
   * @brief Sends data on a stream.
   */
  void SendOnStream(uint64_t stream_id, const std::vector<uint8_t> &data,
                    bool fin = false) {
    if (!connection_ || connection_->GetState() != ConnectionState::Connected) {
      return;
    }

    auto stream = connection_->GetOrCreateStream(stream_id);
    auto frames = stream->Write(data, fin);

    std::vector<QuicFrame> quic_frames;
    for (auto &sf : frames) {
      quic_frames.push_back(std::move(sf));
    }

    auto pkt = connection_->CreatePacket(std::move(quic_frames));
    auto bytes = pkt.Serialize();
    connection_->AddBytesSent(bytes.size());
    sender_.Send(server_address_, bytes);
  }

  /**
   * @brief Sends string data on a stream.
   */
  void SendOnStream(uint64_t stream_id, const std::string &data,
                    bool fin = false) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    SendOnStream(stream_id, bytes, fin);
  }

  /**
   * @brief Returns the current connection, or nullptr.
   */
  std::shared_ptr<QuicConnection> GetConnection() const { return connection_; }

  /**
   * @brief Returns connection state.
   */
  ConnectionState GetConnectionState() const {
    if (!connection_) return ConnectionState::Closed;
    return connection_->GetState();
  }

  /**
   * @brief Returns statistics for the current connection.
   */
  QuicStats GetStats() const {
    if (!connection_) return {};
    return connection_->GetStats();
  }

  /**
   * @brief Gets the locally bound port.
   */
  uint16_t GetLocalPort() const { return sender_.GetLocalPort(); }

  /**
   * @brief Sets the receive buffer size.
   */
  void SetRecvBufferSize(int size) { sender_.SetRecvBufferSize(size); }

  /**
   * @brief Sets the send buffer size.
   */
  void SetSendBufferSize(int size) { sender_.SetSendBufferSize(size); }

 private:
  void HandleIncomingPacket(const cppudpnet::PeerAddress &peer,
                            const std::vector<uint8_t> &data) {
    QuicPacket pkt;
    if (!QuicPacket::Deserialize(data, pkt)) {
      internal::Log(LogSeverity::Warn, "QuicClient",
                    "Failed to deserialize packet");
      return;
    }

    if (!connection_) return;

    for (const auto &frame : pkt.frames) {
      std::visit(
          [this, &pkt](auto &&f) {
            using T = std::decay_t<decltype(f)>;

            if constexpr (std::is_same_v<T, HandshakeFrame>) {
              if (f.type == HandshakeFrame::Type::ServerHello &&
                  connection_->GetState() == ConnectionState::Handshaking) {
                // Complete handshake
                connection_->SetRemoteConnectionId(f.source_connection_id);
                connection_->SetState(ConnectionState::Connected);
                connection_->Touch();
                internal::Log(LogSeverity::Info, "QuicClient",
                              "Handshake complete");
              }
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
              connection_->Touch();
              connection_->RecordReceivedPacket(pkt.packet_number);
              connection_->AddBytesReceived(f.data.size());

              auto stream = connection_->GetOrCreateStream(f.stream_id);
              stream->OnStreamFrame(f);

              // Send ACK
              SendAck();

              if (stream_data_handler_) {
                stream_data_handler_(f.stream_id, f.data, f.fin);
              }
            } else if constexpr (std::is_same_v<T, AckFrame>) {
              connection_->ProcessAck(f);
            } else if constexpr (std::is_same_v<T, PingFrame>) {
              connection_->Touch();
              connection_->RecordReceivedPacket(pkt.packet_number);
              SendAck();
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
              connection_->SetState(ConnectionState::Closed);
              internal::Log(LogSeverity::Info, "QuicClient",
                            "Connection closed by server: " + f.reason);
            } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
              auto stream = connection_->GetStream(f.stream_id);
              if (stream) {
                stream->Reset(f.error_code);
              }
            }
          },
          frame);
    }
  }

  void SendAck() {
    if (!connection_) return;
    auto ack = connection_->GenerateAck();
    std::vector<QuicFrame> frames;
    frames.push_back(std::move(ack));
    auto pkt = connection_->CreatePacket(std::move(frames));
    auto bytes = pkt.Serialize();
    connection_->AddBytesSent(bytes.size());
    sender_.Send(server_address_, bytes);
  }

  void MaintenanceLoop() {
    while (running_.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      if (!connection_ ||
          connection_->GetState() != ConnectionState::Connected) {
        continue;
      }

      // Process retransmissions
      auto retransmits = connection_->GetRetransmissions();
      for (auto &pkt : retransmits) {
        auto bytes = pkt.Serialize();
        connection_->AddBytesSent(bytes.size());
        sender_.Send(server_address_, bytes);
      }
    }
  }

  cppudpnet::UdpSender sender_;

  std::atomic<bool> running_{false};
  std::thread maintenance_thread_;

  cppudpnet::PeerAddress server_address_;
  std::shared_ptr<QuicConnection> connection_;

  std::function<void(uint64_t, const std::vector<uint8_t> &, bool)>
      stream_data_handler_;
  std::function<void(int, const std::string &)> error_handler_;
};

// ============================================================================
// Throughput Tracker
// ============================================================================

/**
 * @brief Sliding-window throughput tracker for QuicServer or QuicClient.
 *
 * Polls stats in the background and computes send/recv throughput
 * over a 1-second sliding window.
 */
template <typename T>
class ThroughputTracker {
 public:
  explicit ThroughputTracker(
      T &target,
      std::chrono::milliseconds poll_interval = std::chrono::milliseconds(100))
      : target_(target), poll_interval_(poll_interval) {
    running_.store(true);
    thread_ = std::thread([this]() { PollLoop(); });
  }

  ~ThroughputTracker() {
    running_.store(false);
    if (thread_.joinable()) thread_.join();
  }

  ThroughputTracker(const ThroughputTracker &) = delete;
  ThroughputTracker &operator=(const ThroughputTracker &) = delete;

  double GetSendThroughputBytesPerSec() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return send_throughput_;
  }

  double GetRecvThroughputBytesPerSec() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return recv_throughput_;
  }

 private:
  struct Sample {
    std::chrono::steady_clock::time_point time;
    uint64_t bytes_sent;
    uint64_t bytes_received;
  };

  void PollLoop() {
    while (running_.load()) {
      auto stats = target_.GetStats();
      auto now = std::chrono::steady_clock::now();

      Sample sample;
      sample.time = now;
      sample.bytes_sent = stats.bytes_sent;
      sample.bytes_received = stats.bytes_received;

      {
        std::lock_guard<std::mutex> lock(mtx_);
        samples_.push_back(sample);

        // Remove samples older than 1 second
        auto cutoff = now - std::chrono::seconds(1);
        while (!samples_.empty() && samples_.front().time < cutoff) {
          samples_.pop_front();
        }

        // Calculate throughput
        if (samples_.size() >= 2) {
          auto &oldest = samples_.front();
          auto &newest = samples_.back();
          double elapsed =
              std::chrono::duration<double>(newest.time - oldest.time).count();
          if (elapsed > 0.0) {
            send_throughput_ =
                (newest.bytes_sent - oldest.bytes_sent) / elapsed;
            recv_throughput_ =
                (newest.bytes_received - oldest.bytes_received) / elapsed;
          }
        }
      }

      std::this_thread::sleep_for(poll_interval_);
    }
  }

  T &target_;
  std::chrono::milliseconds poll_interval_;
  std::atomic<bool> running_{false};
  std::thread thread_;

  mutable std::mutex mtx_;
  std::deque<Sample> samples_;
  double send_throughput_ = 0.0;
  double recv_throughput_ = 0.0;
};

}  // namespace cppquic
