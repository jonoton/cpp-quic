#pragma once

#include <algorithm>
#include <cmath>
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace cppquic {
constexpr int VERSION_MAJOR = 1;
constexpr int VERSION_MINOR = 3;
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

inline bool EncryptData(const std::vector<uint8_t> &key,
                        const std::vector<uint8_t> &iv,
                        const std::vector<uint8_t> &plaintext,
                        std::vector<uint8_t> &ciphertext_out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  ciphertext_out.resize(plaintext.size() + 16);
  int len = 0;
  int ciphertext_len = 0;

  if (1 != EVP_EncryptUpdate(ctx, ciphertext_out.data(), &len, plaintext.data(),
                             plaintext.size())) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext_out.data() + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len += len;

  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                               ciphertext_out.data() + ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_out.resize(ciphertext_len + 16);

  EVP_CIPHER_CTX_free(ctx);
  return true;
}

inline bool DecryptData(const std::vector<uint8_t> &key,
                        const std::vector<uint8_t> &iv,
                        const std::vector<uint8_t> &ciphertext_with_tag,
                        std::vector<uint8_t> &plaintext_out) {
  if (ciphertext_with_tag.size() < 16) return false;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  int ciphertext_len = ciphertext_with_tag.size() - 16;
  plaintext_out.resize(ciphertext_len);
  int len = 0;
  int plaintext_len = 0;

  if (1 != EVP_DecryptUpdate(ctx, plaintext_out.data(), &len,
                             ciphertext_with_tag.data(), ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  plaintext_len = len;

  void *tag_ptr =
      const_cast<uint8_t *>(ciphertext_with_tag.data() + ciphertext_len);
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_ptr)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  int ret = EVP_DecryptFinal_ex(ctx, plaintext_out.data() + len, &len);
  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0) {
    plaintext_len += len;
    plaintext_out.resize(plaintext_len);
    return true;
  } else {
    return false;
  }
}

// QUIC variable-length integer helper functions (RFC 9000 Section 16)
inline void WriteVarInt(std::vector<uint8_t> &buf, uint64_t val) {
  if (val <= 63) {
    buf.push_back(static_cast<uint8_t>(val));
  } else if (val <= 16383) {
    buf.push_back(static_cast<uint8_t>(0x40 | ((val >> 8) & 0x3F)));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
  } else if (val <= 1073741823) {
    buf.push_back(static_cast<uint8_t>(0x80 | ((val >> 24) & 0x3F)));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
  } else {
    buf.push_back(static_cast<uint8_t>(0xC0 | ((val >> 56) & 0x3F)));
    buf.push_back(static_cast<uint8_t>((val >> 48) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 40) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 32) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
  }
}

inline bool ReadVarInt(const uint8_t *buf, size_t len, size_t &offset,
                       uint64_t &out) {
  if (offset >= len) return false;
  uint8_t first = buf[offset];
  uint8_t type = first >> 6;
  size_t bytes_needed = 0;
  if (type == 0)
    bytes_needed = 1;
  else if (type == 1)
    bytes_needed = 2;
  else if (type == 2)
    bytes_needed = 4;
  else if (type == 3)
    bytes_needed = 8;

  if (offset + bytes_needed > len) return false;

  if (bytes_needed == 1) {
    out = first & 0x3F;
  } else if (bytes_needed == 2) {
    out = ((first & 0x3F) << 8) | buf[offset + 1];
  } else if (bytes_needed == 4) {
    out = ((first & 0x3F) << 24) | (buf[offset + 1] << 16) |
          (buf[offset + 2] << 8) | buf[offset + 3];
  } else {
    out = 0;
    out |= (static_cast<uint64_t>(first & 0x3F) << 56);
    out |= (static_cast<uint64_t>(buf[offset + 1]) << 48);
    out |= (static_cast<uint64_t>(buf[offset + 2]) << 40);
    out |= (static_cast<uint64_t>(buf[offset + 3]) << 32);
    out |= (static_cast<uint64_t>(buf[offset + 4]) << 24);
    out |= (static_cast<uint64_t>(buf[offset + 5]) << 16);
    out |= (static_cast<uint64_t>(buf[offset + 6]) << 8);
    out |= static_cast<uint64_t>(buf[offset + 7]);
  }
  offset += bytes_needed;
  return true;
}

// RFC 9001 HKDF Key Derivation functions
inline std::vector<uint8_t> HKDF_Extract(const std::vector<uint8_t> &salt,
                                         const std::vector<uint8_t> &ikm) {
  std::vector<uint8_t> prk(32);
  unsigned int prk_len = 32;
  HMAC(EVP_sha256(), salt.data(), salt.size(), ikm.data(), ikm.size(),
       prk.data(), &prk_len);
  prk.resize(prk_len);
  return prk;
}

inline std::vector<uint8_t> HKDF_Expand(const std::vector<uint8_t> &prk,
                                        const std::vector<uint8_t> &info,
                                        size_t L) {
  std::vector<uint8_t> okm;
  okm.reserve(L);
  std::vector<uint8_t> T;
  uint8_t counter = 1;
  while (okm.size() < L) {
    std::vector<uint8_t> input = T;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(counter);

    std::vector<uint8_t> tmp(32);
    unsigned int tmp_len = 32;
    HMAC(EVP_sha256(), prk.data(), prk.size(), input.data(), input.size(),
         tmp.data(), &tmp_len);
    tmp.resize(tmp_len);

    size_t remaining = L - okm.size();
    size_t to_copy = std::min(remaining, (size_t)tmp.size());
    okm.insert(okm.end(), tmp.begin(), tmp.begin() + to_copy);
    T = std::move(tmp);
    counter++;
  }
  return okm;
}

inline std::vector<uint8_t> HKDF_Expand_Label(
    const std::vector<uint8_t> &secret, const std::string &label,
    const std::vector<uint8_t> &context, size_t length) {
  std::string full_label = "tls13 " + label;
  std::vector<uint8_t> hkdf_label;
  hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(length & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
  hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());
  hkdf_label.push_back(static_cast<uint8_t>(context.size()));
  hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());
  return HKDF_Expand(secret, hkdf_label, length);
}

// In-Memory Self-Signed Certificate Generation
inline bool GenerateSelfSignedCert(SSL_CTX *ctx) {
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!pctx) return false;
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return false;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return false;
  }
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return false;
  }
  EVP_PKEY_CTX_free(pctx);

  X509 *x509 = X509_new();
  if (!x509) {
    EVP_PKEY_free(pkey);
    return false;
  }

  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  // 1 year expiry

  X509_set_pubkey(x509, pkey);

  X509_NAME *name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                             (const unsigned char *)"US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                             (const unsigned char *)"cppquic", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x509, name);

  if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return false;
  }

  if (SSL_CTX_use_certificate(ctx, x509) <= 0) {
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return false;
  }
  if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return false;
  }

  X509_free(x509);
  EVP_PKEY_free(pkey);
  return true;
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
  PADDING = 0x00,
  PING = 0x01,
  ACK = 0x02,
  RESET_STREAM = 0x04,
  STOP_SENDING = 0x05,
  CRYPTO = 0x06,
  NEW_TOKEN = 0x07,
  STREAM = 0x08,  // 0x08 to 0x0F
  MAX_DATA = 0x10,
  MAX_STREAM_DATA = 0x11,
  MAX_STREAMS_BIDI = 0x12,
  MAX_STREAMS_UNI = 0x13,
  DATA_BLOCKED = 0x14,
  STREAM_DATA_BLOCKED = 0x15,
  STREAMS_BLOCKED_BIDI = 0x16,
  STREAMS_BLOCKED_UNI = 0x17,
  NEW_CONNECTION_ID = 0x18,
  RETIRE_CONNECTION_ID = 0x19,
  PATH_CHALLENGE = 0x1a,
  PATH_RESPONSE = 0x1b,
  CONNECTION_CLOSE = 0x1c,  // 0x1c or 0x1d
  HANDSHAKE_DONE = 0x1e,
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
 * @brief A CRYPTO frame for connection establishment carrying TLS messages.
 */
struct CryptoFrame {
  uint64_t offset = 0;
  std::vector<uint8_t> data;
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
 * @brief A PADDING frame for padding packets.
 */
struct PaddingFrame {};

/**
 * @brief A STOP_SENDING frame to request termination of a stream.
 */
struct StopSendingFrame {
  uint64_t stream_id = 0;
  uint64_t error_code = 0;
};

/**
 * @brief A NEW_TOKEN frame to provide a client with a token.
 */
struct NewTokenFrame {
  std::vector<uint8_t> token;
};

/**
 * @brief A MAX_DATA frame to increase connection flow control limit.
 */
struct MaxDataFrame {
  uint64_t max_data = 0;
};

/**
 * @brief A MAX_STREAM_DATA frame to increase stream flow control limit.
 */
struct MaxStreamDataFrame {
  uint64_t stream_id = 0;
  uint64_t max_stream_data = 0;
};

/**
 * @brief A MAX_STREAMS frame to increase stream limits.
 */
struct MaxStreamsFrame {
  bool unidirectional = false;
  uint64_t max_streams = 0;
};

/**
 * @brief A DATA_BLOCKED frame to signal connection flow control limit reached.
 */
struct DataBlockedFrame {
  uint64_t data_limit = 0;
};

/**
 * @brief A STREAM_DATA_BLOCKED frame to signal stream flow control limit
 * reached.
 */
struct StreamDataBlockedFrame {
  uint64_t stream_id = 0;
  uint64_t stream_data_limit = 0;
};

/**
 * @brief A STREAMS_BLOCKED frame to signal stream limit reached.
 */
struct StreamsBlockedFrame {
  bool unidirectional = false;
  uint64_t stream_limit = 0;
};

/**
 * @brief A NEW_CONNECTION_ID frame to offer an alternative Connection ID.
 */
struct NewConnectionIdFrame {
  uint64_t sequence_number = 0;
  uint64_t retire_prior_to = 0;
  ConnectionId connection_id;
  std::vector<uint8_t> stateless_reset_token;
};

/**
 * @brief A RETIRE_CONNECTION_ID frame to retire an alternative Connection ID.
 */
struct RetireConnectionIdFrame {
  uint64_t sequence_number = 0;
};

/**
 * @brief A PATH_CHALLENGE frame for path validation.
 */
struct PathChallengeFrame {
  uint8_t data[8] = {0};
};

/**
 * @brief A PATH_RESPONSE frame responding to a path challenge.
 */
struct PathResponseFrame {
  uint8_t data[8] = {0};
};

/**
 * @brief A HANDSHAKE_DONE frame signals handshake completion.
 */
struct HandshakeDoneFrame {};

/**
 * @brief A variant type encompassing all QUIC frame types.
 */
using QuicFrame =
    std::variant<StreamFrame, AckFrame, CryptoFrame, PingFrame,
                 ConnectionCloseFrame, ResetStreamFrame, PaddingFrame,
                 StopSendingFrame, NewTokenFrame, MaxDataFrame,
                 MaxStreamDataFrame, MaxStreamsFrame, DataBlockedFrame,
                 StreamDataBlockedFrame, StreamsBlockedFrame,
                 NewConnectionIdFrame, RetireConnectionIdFrame,
                 PathChallengeFrame, PathResponseFrame, HandshakeDoneFrame>;

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
          uint8_t type = 0x08 | 0x04 | 0x02 | (f.fin ? 0x01 : 0x00);
          WriteUint8(buf, type);
          WriteVarInt(buf, f.stream_id);
          WriteVarInt(buf, f.offset);
          WriteVarInt(buf, f.data.size());
          WriteBytes(buf, f.data.data(), f.data.size());

        } else if constexpr (std::is_same_v<T, AckFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::ACK));
          WriteVarInt(buf, f.largest_acknowledged);
          WriteVarInt(buf, f.ack_delay_us);
          WriteVarInt(buf, f.acknowledged_packets.size());
          for (auto pkt : f.acknowledged_packets) {
            WriteVarInt(buf, pkt);
          }

        } else if constexpr (std::is_same_v<T, CryptoFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::CRYPTO));
          WriteVarInt(buf, f.offset);
          WriteVarInt(buf, f.data.size());
          WriteBytes(buf, f.data.data(), f.data.size());

        } else if constexpr (std::is_same_v<T, PingFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::PING));

        } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::CONNECTION_CLOSE));
          WriteVarInt(buf, f.error_code);
          WriteVarInt(buf, 0);  // Frame Type
          WriteVarInt(buf, f.reason.size());
          WriteBytes(buf, reinterpret_cast<const uint8_t *>(f.reason.data()),
                     f.reason.size());

        } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::RESET_STREAM));
          WriteVarInt(buf, f.stream_id);
          WriteVarInt(buf, f.error_code);
          WriteVarInt(buf, f.final_size);

        } else if constexpr (std::is_same_v<T, PaddingFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::PADDING));

        } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::STOP_SENDING));
          WriteVarInt(buf, f.stream_id);
          WriteVarInt(buf, f.error_code);

        } else if constexpr (std::is_same_v<T, NewTokenFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::NEW_TOKEN));
          WriteVarInt(buf, f.token.size());
          WriteBytes(buf, f.token.data(), f.token.size());

        } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::MAX_DATA));
          WriteVarInt(buf, f.max_data);

        } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::MAX_STREAM_DATA));
          WriteVarInt(buf, f.stream_id);
          WriteVarInt(buf, f.max_stream_data);

        } else if constexpr (std::is_same_v<T, MaxStreamsFrame>) {
          uint8_t type =
              f.unidirectional
                  ? static_cast<uint8_t>(FrameType::MAX_STREAMS_UNI)
                  : static_cast<uint8_t>(FrameType::MAX_STREAMS_BIDI);
          WriteVarInt(buf, type);
          WriteVarInt(buf, f.max_streams);

        } else if constexpr (std::is_same_v<T, DataBlockedFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::DATA_BLOCKED));
          WriteVarInt(buf, f.data_limit);

        } else if constexpr (std::is_same_v<T, StreamDataBlockedFrame>) {
          WriteVarInt(buf,
                      static_cast<uint64_t>(FrameType::STREAM_DATA_BLOCKED));
          WriteVarInt(buf, f.stream_id);
          WriteVarInt(buf, f.stream_data_limit);

        } else if constexpr (std::is_same_v<T, StreamsBlockedFrame>) {
          uint8_t type =
              f.unidirectional
                  ? static_cast<uint8_t>(FrameType::STREAMS_BLOCKED_UNI)
                  : static_cast<uint8_t>(FrameType::STREAMS_BLOCKED_BIDI);
          WriteVarInt(buf, type);
          WriteVarInt(buf, f.stream_limit);

        } else if constexpr (std::is_same_v<T, NewConnectionIdFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::NEW_CONNECTION_ID));
          WriteVarInt(buf, f.sequence_number);
          WriteVarInt(buf, f.retire_prior_to);
          WriteUint8(buf, 8);  // Connection ID Length (fixed to 8)
          f.connection_id.Serialize(buf);
          std::vector<uint8_t> reset_token = f.stateless_reset_token;
          reset_token.resize(16, 0);  // Ensure exactly 16 bytes
          WriteBytes(buf, reset_token.data(), 16);

        } else if constexpr (std::is_same_v<T, RetireConnectionIdFrame>) {
          WriteVarInt(buf,
                      static_cast<uint64_t>(FrameType::RETIRE_CONNECTION_ID));
          WriteVarInt(buf, f.sequence_number);

        } else if constexpr (std::is_same_v<T, PathChallengeFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::PATH_CHALLENGE));
          WriteBytes(buf, f.data, 8);

        } else if constexpr (std::is_same_v<T, PathResponseFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::PATH_RESPONSE));
          WriteBytes(buf, f.data, 8);

        } else if constexpr (std::is_same_v<T, HandshakeDoneFrame>) {
          WriteVarInt(buf, static_cast<uint64_t>(FrameType::HANDSHAKE_DONE));
        }
      },
      frame);
}

// Deserialize one frame from the buffer at offset. Returns false on failure.
inline bool DeserializeFrame(const uint8_t *buf, size_t len, size_t &offset,
                             QuicFrame &out) {
  uint64_t frame_type_val = 0;
  if (!ReadVarInt(buf, len, offset, frame_type_val)) return false;

  uint8_t frame_type_raw = static_cast<uint8_t>(frame_type_val);

  if (frame_type_raw >= 0x08 && frame_type_raw <= 0x0F) {
    StreamFrame f;
    f.fin = (frame_type_raw & 0x01) != 0;
    if (!ReadVarInt(buf, len, offset, f.stream_id)) return false;
    if (frame_type_raw & 0x04) {
      if (!ReadVarInt(buf, len, offset, f.offset)) return false;
    } else {
      f.offset = 0;
    }
    uint64_t data_len = 0;
    if (!ReadVarInt(buf, len, offset, data_len)) return false;
    if (offset + data_len > len) return false;
    f.data.assign(buf + offset, buf + offset + data_len);
    offset += data_len;
    out = std::move(f);
    return true;
  }

  auto frame_type = static_cast<FrameType>(frame_type_raw);

  switch (frame_type) {
    case FrameType::PADDING: {
      out = PaddingFrame{};
      return true;
    }
    case FrameType::PING: {
      out = PingFrame{};
      return true;
    }
    case FrameType::ACK: {
      AckFrame f;
      if (!ReadVarInt(buf, len, offset, f.largest_acknowledged)) return false;
      if (!ReadVarInt(buf, len, offset, f.ack_delay_us)) return false;
      uint64_t count = 0;
      if (!ReadVarInt(buf, len, offset, count)) return false;
      f.acknowledged_packets.resize(count);
      for (uint64_t i = 0; i < count; ++i) {
        if (!ReadVarInt(buf, len, offset, f.acknowledged_packets[i]))
          return false;
      }
      out = std::move(f);
      return true;
    }
    case FrameType::RESET_STREAM: {
      ResetStreamFrame f;
      if (!ReadVarInt(buf, len, offset, f.stream_id)) return false;
      if (!ReadVarInt(buf, len, offset, f.error_code)) return false;
      if (!ReadVarInt(buf, len, offset, f.final_size)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::STOP_SENDING: {
      StopSendingFrame f;
      if (!ReadVarInt(buf, len, offset, f.stream_id)) return false;
      if (!ReadVarInt(buf, len, offset, f.error_code)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::CRYPTO: {
      CryptoFrame f;
      if (!ReadVarInt(buf, len, offset, f.offset)) return false;
      uint64_t crypto_len = 0;
      if (!ReadVarInt(buf, len, offset, crypto_len)) return false;
      if (offset + crypto_len > len) return false;
      f.data.assign(buf + offset, buf + offset + crypto_len);
      offset += crypto_len;
      out = std::move(f);
      return true;
    }
    case FrameType::NEW_TOKEN: {
      NewTokenFrame f;
      uint64_t token_len = 0;
      if (!ReadVarInt(buf, len, offset, token_len)) return false;
      if (offset + token_len > len) return false;
      f.token.assign(buf + offset, buf + offset + token_len);
      offset += token_len;
      out = std::move(f);
      return true;
    }
    case FrameType::MAX_DATA: {
      MaxDataFrame f;
      if (!ReadVarInt(buf, len, offset, f.max_data)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::MAX_STREAM_DATA: {
      MaxStreamDataFrame f;
      if (!ReadVarInt(buf, len, offset, f.stream_id)) return false;
      if (!ReadVarInt(buf, len, offset, f.max_stream_data)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::MAX_STREAMS_BIDI:
    case FrameType::MAX_STREAMS_UNI: {
      MaxStreamsFrame f;
      f.unidirectional = (frame_type == FrameType::MAX_STREAMS_UNI);
      if (!ReadVarInt(buf, len, offset, f.max_streams)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::DATA_BLOCKED: {
      DataBlockedFrame f;
      if (!ReadVarInt(buf, len, offset, f.data_limit)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::STREAM_DATA_BLOCKED: {
      StreamDataBlockedFrame f;
      if (!ReadVarInt(buf, len, offset, f.stream_id)) return false;
      if (!ReadVarInt(buf, len, offset, f.stream_data_limit)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::STREAMS_BLOCKED_BIDI:
    case FrameType::STREAMS_BLOCKED_UNI: {
      StreamsBlockedFrame f;
      f.unidirectional = (frame_type == FrameType::STREAMS_BLOCKED_UNI);
      if (!ReadVarInt(buf, len, offset, f.stream_limit)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::NEW_CONNECTION_ID: {
      NewConnectionIdFrame f;
      if (!ReadVarInt(buf, len, offset, f.sequence_number)) return false;
      if (!ReadVarInt(buf, len, offset, f.retire_prior_to)) return false;
      uint8_t cid_len = 0;
      if (!ReadUint8(buf, len, offset, cid_len)) return false;
      if (cid_len != 8) return false;
      if (!ConnectionId::Deserialize(buf, len, offset, f.connection_id))
        return false;
      if (offset + 16 > len) return false;
      f.stateless_reset_token.assign(buf + offset, buf + offset + 16);
      offset += 16;
      out = std::move(f);
      return true;
    }
    case FrameType::RETIRE_CONNECTION_ID: {
      RetireConnectionIdFrame f;
      if (!ReadVarInt(buf, len, offset, f.sequence_number)) return false;
      out = std::move(f);
      return true;
    }
    case FrameType::PATH_CHALLENGE: {
      PathChallengeFrame f;
      if (offset + 8 > len) return false;
      std::memcpy(f.data, buf + offset, 8);
      offset += 8;
      out = std::move(f);
      return true;
    }
    case FrameType::PATH_RESPONSE: {
      PathResponseFrame f;
      if (offset + 8 > len) return false;
      std::memcpy(f.data, buf + offset, 8);
      offset += 8;
      out = std::move(f);
      return true;
    }
    case FrameType::CONNECTION_CLOSE: {
      ConnectionCloseFrame f;
      if (!ReadVarInt(buf, len, offset, f.error_code)) return false;
      uint64_t frame_type_close = 0;
      if (!ReadVarInt(buf, len, offset, frame_type_close)) return false;
      uint64_t reason_len = 0;
      if (!ReadVarInt(buf, len, offset, reason_len)) return false;
      if (offset + reason_len > len) return false;
      f.reason.assign(reinterpret_cast<const char *>(buf + offset), reason_len);
      offset += reason_len;
      out = std::move(f);
      return true;
    }
    case FrameType::HANDSHAKE_DONE: {
      out = HandshakeDoneFrame{};
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
namespace internal {
inline SSL_CTX *GetSSLContext(bool is_server) {
  static std::mutex mtx;
  std::lock_guard<std::mutex> lock(mtx);
  static SSL_CTX *client_ctx = nullptr;
  static SSL_CTX *server_ctx = nullptr;
  static bool initialized = false;
  if (!initialized) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    initialized = true;
  }
  if (is_server) {
    if (!server_ctx) {
      server_ctx = SSL_CTX_new(TLS_server_method());
      SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION);
      if (!GenerateSelfSignedCert(server_ctx)) {
        Log(LogSeverity::Error, "GetSSLContext",
            "Failed to generate self-signed certificate");
      }
    }
    return server_ctx;
  } else {
    if (!client_ctx) {
      client_ctx = SSL_CTX_new(TLS_client_method());
      SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION);
    }
    return client_ctx;
  }
}

inline void DeriveInitialKeys(const ConnectionId &dest_conn_id, bool is_server,
                              std::vector<uint8_t> &read_key,
                              std::vector<uint8_t> &read_iv,
                              std::vector<uint8_t> &write_key,
                              std::vector<uint8_t> &write_iv) {
  // RFC 9001 §5.2 — QUIC v1 initial salt
  const std::vector<uint8_t> salt = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                     0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                     0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
  std::vector<uint8_t> dest_conn_id_bytes(dest_conn_id.data,
                                          dest_conn_id.data + 8);
  std::vector<uint8_t> initial_secret = HKDF_Extract(salt, dest_conn_id_bytes);

  std::vector<uint8_t> client_secret =
      HKDF_Expand_Label(initial_secret, "client in", {}, 32);
  std::vector<uint8_t> server_secret =
      HKDF_Expand_Label(initial_secret, "server in", {}, 32);

  if (is_server) {
    read_key = HKDF_Expand_Label(client_secret, "quic key", {}, 16);
    read_iv = HKDF_Expand_Label(client_secret, "quic iv", {}, 12);
    write_key = HKDF_Expand_Label(server_secret, "quic key", {}, 16);
    write_iv = HKDF_Expand_Label(server_secret, "quic iv", {}, 12);
  } else {
    read_key = HKDF_Expand_Label(server_secret, "quic key", {}, 16);
    read_iv = HKDF_Expand_Label(server_secret, "quic iv", {}, 12);
    write_key = HKDF_Expand_Label(client_secret, "quic key", {}, 16);
    write_iv = HKDF_Expand_Label(client_secret, "quic iv", {}, 12);
  }

  Log(LogSeverity::Info, "DeriveKeys",
      std::string(is_server ? "Server" : "Client") +
          " derived initial keys for dest_conn_id " + dest_conn_id.ToHex() +
          ": read_key=" +
          (read_key.empty() ? ""
                            : ConnectionId{read_key[0], read_key[1],
                                           read_key[2], read_key[3], 0, 0, 0, 0}
                                  .ToHex()
                                  .substr(0, 8)) +
          ", write_key=" +
          (write_key.empty()
               ? ""
               : ConnectionId{write_key[0], write_key[1], write_key[2],
                              write_key[3], 0, 0, 0, 0}
                     .ToHex()
                     .substr(0, 8)));
}

inline void DeriveZeroRTTKeys(const ConnectionId &dest_conn_id, bool is_server,
                              std::vector<uint8_t> &read_key,
                              std::vector<uint8_t> &read_iv,
                              std::vector<uint8_t> &write_key,
                              std::vector<uint8_t> &write_iv) {
  const std::vector<uint8_t> salt = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                     0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                                     0xee, 0xff, 0x00, 0x11, 0x22, 0x33};
  std::vector<uint8_t> dest_conn_id_bytes(dest_conn_id.data,
                                          dest_conn_id.data + 8);
  std::vector<uint8_t> initial_secret = HKDF_Extract(salt, dest_conn_id_bytes);
  std::vector<uint8_t> client_early =
      HKDF_Expand_Label(initial_secret, "client early", {}, 32);
  std::vector<uint8_t> server_early =
      HKDF_Expand_Label(initial_secret, "server early", {}, 32);

  if (is_server) {
    read_key = HKDF_Expand_Label(client_early, "quic key", {}, 16);
    read_iv = HKDF_Expand_Label(client_early, "quic iv", {}, 12);
    write_key = HKDF_Expand_Label(server_early, "quic key", {}, 16);
    write_iv = HKDF_Expand_Label(server_early, "quic iv", {}, 12);
  } else {
    read_key = HKDF_Expand_Label(server_early, "quic key", {}, 16);
    read_iv = HKDF_Expand_Label(server_early, "quic iv", {}, 12);
    write_key = HKDF_Expand_Label(client_early, "quic key", {}, 16);
    write_iv = HKDF_Expand_Label(client_early, "quic iv", {}, 12);
  }
}

inline void DeriveStatelessResetToken(const ConnectionId &cid,
                                      uint8_t token[16]) {
  const std::vector<uint8_t> salt = {0x73, 0x74, 0x61, 0x74, 0x65, 0x6c, 0x65,
                                     0x73, 0x73, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
                                     0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f};
  std::vector<uint8_t> cid_bytes(cid.data, cid.data + 8);
  std::vector<uint8_t> secret = HKDF_Extract(salt, cid_bytes);
  std::vector<uint8_t> tok = HKDF_Expand_Label(secret, "reset token", {}, 16);
  std::memcpy(token, tok.data(), 16);
}
}  // namespace internal

struct QuicPacket {
  uint8_t packet_type =
      0;  // 0 = 1-RTT (Short Header), 1 = Initial, 2 = Handshake
  ConnectionId connection_id;
  ConnectionId source_connection_id;
  uint64_t packet_number = 0;
  std::vector<QuicFrame> frames;

  /**
   * @brief Serializes this packet into a byte buffer.
   */
  std::vector<uint8_t> Serialize(
      const std::vector<uint8_t> *key = nullptr,
      const std::vector<uint8_t> *iv = nullptr) const {
    std::vector<uint8_t> buf;
    buf.reserve(256);

    std::vector<uint8_t> payload;
    payload.reserve(256);
    for (const auto &frame : frames) {
      internal::SerializeFrame(payload, frame);
    }

    std::vector<uint8_t> final_payload;
    if (key && iv && !key->empty() && !iv->empty()) {
      std::vector<uint8_t> pkt_iv = *iv;
      for (size_t i = 0; i < 8 && i < pkt_iv.size(); ++i) {
        pkt_iv[pkt_iv.size() - 1 - i] ^= (packet_number >> (i * 8)) & 0xFF;
      }
      std::vector<uint8_t> ciphertext;
      if (internal::EncryptData(*key, pkt_iv, payload, ciphertext)) {
        final_payload = std::move(ciphertext);
      } else {
        final_payload = std::move(payload);  // fallback
      }
    } else {
      final_payload = std::move(payload);
    }

    if (packet_type == 1 || packet_type == 2 || packet_type == 3) {
      // Long Header (Initial, Handshake, or 0-RTT)
      uint8_t first = 0;
      if (packet_type == 1)
        first = 0xc3;
      else if (packet_type == 2)
        first = 0xe3;
      else if (packet_type == 3)
        first = 0xd3;

      internal::WriteUint8(buf, first);
      internal::WriteUint32(buf, 0x00000001);  // Version (QUIC v1)
      internal::WriteUint8(buf, 8);            // Dest ID Len
      connection_id.Serialize(buf);
      internal::WriteUint8(buf, 8);  // Src ID Len
      source_connection_id.Serialize(buf);

      if (packet_type == 1) {
        internal::WriteVarInt(buf, 0);  // Token Len
      }

      // Length = Packet Number size (4 bytes) + final_payload size
      uint64_t packet_len = 4 + final_payload.size();
      internal::WriteVarInt(buf, packet_len);

      internal::WriteUint32(buf, static_cast<uint32_t>(packet_number));
      buf.insert(buf.end(), final_payload.begin(), final_payload.end());
    } else {
      // Short Header (1-RTT)
      internal::WriteUint8(buf, 0x43);
      connection_id.Serialize(buf);
      internal::WriteUint32(buf, static_cast<uint32_t>(packet_number));
      buf.insert(buf.end(), final_payload.begin(), final_payload.end());
    }

    return buf;
  }

  /**
   * @brief Peeks the Connection ID from the packet data without decrypting.
   */
  static bool PeekConnectionId(const std::vector<uint8_t> &data,
                               ConnectionId &out) {
    if (data.empty()) return false;
    uint8_t first = data[0];
    size_t offset = 0;
    if (first & 0x80) {
      // Long Header
      if (data.size() < 6) return false;
      uint8_t dest_len = data[5];
      if (dest_len != 8) return false;
      if (data.size() < 14) return false;
      offset = 6;
    } else {
      // Short Header
      if (data.size() < 9) return false;
      offset = 1;
    }
    return ConnectionId::Deserialize(data.data(), data.size(), offset, out);
  }

  static std::vector<std::vector<uint8_t>> SplitCoalescedPackets(
      const std::vector<uint8_t> &data) {
    std::vector<std::vector<uint8_t>> packets;
    if (data.empty()) return packets;

    const uint8_t *buf = data.data();
    size_t len = data.size();
    size_t offset = 0;

    while (offset < len) {
      size_t packet_start = offset;
      uint8_t first = 0;
      if (!internal::ReadUint8(buf, len, offset, first)) break;

      if (first & 0x80) {
        // Long Header packet
        uint32_t version = 0;
        if (!internal::ReadUint32(buf, len, offset, version)) break;

        uint8_t dest_len = 0;
        if (!internal::ReadUint8(buf, len, offset, dest_len)) break;
        if (offset + dest_len > len) break;
        offset += dest_len;

        uint8_t src_len = 0;
        if (!internal::ReadUint8(buf, len, offset, src_len)) break;
        if (offset + src_len > len) break;
        offset += src_len;

        uint8_t type = (first >> 4) & 0x03;
        if (type == 0) {  // Initial
          uint64_t token_len = 0;
          if (!internal::ReadVarInt(buf, len, offset, token_len)) break;
          if (offset + token_len > len) break;
          offset += token_len;
        }

        uint64_t packet_len = 0;
        if (!internal::ReadVarInt(buf, len, offset, packet_len)) break;
        if (offset + packet_len > len) break;
        offset += packet_len;

        size_t packet_end = offset;
        packets.push_back(
            std::vector<uint8_t>(buf + packet_start, buf + packet_end));
      } else {
        // Short Header packet (consumes the remaining datagram)
        packets.push_back(std::vector<uint8_t>(buf + packet_start, buf + len));
        break;
      }
    }
    return packets;
  }

  /**
   * @brief Deserializes a packet from a byte buffer.
   * @return true on success, false on malformed data.
   */
  static bool Deserialize(const std::vector<uint8_t> &data, QuicPacket &out,
                          const std::vector<uint8_t> *key = nullptr,
                          const std::vector<uint8_t> *iv = nullptr) {
    if (data.empty()) return false;
    const uint8_t *buf = data.data();
    size_t len = data.size();
    size_t offset = 0;

    uint8_t first = 0;
    if (!internal::ReadUint8(buf, len, offset, first)) return false;

    if (first & 0x80) {
      // Long Header
      uint8_t type = (first >> 4) & 0x03;
      if (type == 0) {
        out.packet_type = 1;  // Initial
      } else if (type == 2) {
        out.packet_type = 2;  // Handshake
      } else if (type == 1) {
        out.packet_type = 3;  // 0-RTT
      } else {
        return false;  // Unsupported long header type
      }

      uint32_t version = 0;
      if (!internal::ReadUint32(buf, len, offset, version)) return false;
      if (version != 0x00000001) return false;

      uint8_t dest_len = 0;
      if (!internal::ReadUint8(buf, len, offset, dest_len)) return false;
      if (dest_len != 8) return false;
      if (!ConnectionId::Deserialize(buf, len, offset, out.connection_id))
        return false;

      uint8_t src_len = 0;
      if (!internal::ReadUint8(buf, len, offset, src_len)) return false;
      if (src_len != 8) return false;
      if (!ConnectionId::Deserialize(buf, len, offset,
                                     out.source_connection_id))
        return false;

      if (out.packet_type == 1) {  // Initial
        uint64_t token_len = 0;
        if (!internal::ReadVarInt(buf, len, offset, token_len)) return false;
        if (token_len > 0) {
          if (offset + token_len > len) return false;
          offset += token_len;  // Skip token
        }
      }

      uint64_t packet_len = 0;
      if (!internal::ReadVarInt(buf, len, offset, packet_len)) return false;
      if (offset + packet_len > len) return false;

      // The packet payload and packet number are inside packet_len
      // Read 4-byte packet number
      uint32_t pkt_num = 0;
      if (!internal::ReadUint32(buf, len, offset, pkt_num)) return false;
      out.packet_number = pkt_num;

      size_t payload_len = packet_len - 4;
      if (offset + payload_len > len) return false;

      std::vector<uint8_t> payload_buf(buf + offset,
                                       buf + offset + payload_len);
      offset += payload_len;

      std::vector<uint8_t> plaintext;
      if (key && iv && !key->empty() && !iv->empty()) {
        std::vector<uint8_t> pkt_iv = *iv;
        for (size_t i = 0; i < 8 && i < pkt_iv.size(); ++i) {
          pkt_iv[pkt_iv.size() - 1 - i] ^=
              (out.packet_number >> (i * 8)) & 0xFF;
        }
        if (!internal::DecryptData(*key, pkt_iv, payload_buf, plaintext)) {
          return false;
        }
      } else {
        plaintext = std::move(payload_buf);
      }

      // Deserialize frames from plaintext
      const uint8_t *p_buf = plaintext.data();
      size_t p_len = plaintext.size();
      size_t p_offset = 0;

      out.frames.clear();
      while (p_offset < p_len) {
        QuicFrame frame;
        if (!internal::DeserializeFrame(p_buf, p_len, p_offset, frame))
          return false;
        out.frames.push_back(std::move(frame));
      }
      return true;
    } else {
      // Short Header (1-RTT)
      out.packet_type = 0;
      if (!ConnectionId::Deserialize(buf, len, offset, out.connection_id))
        return false;

      uint32_t pkt_num = 0;
      if (!internal::ReadUint32(buf, len, offset, pkt_num)) return false;
      out.packet_number = pkt_num;

      std::vector<uint8_t> payload_buf(buf + offset, buf + len);
      offset = len;

      std::vector<uint8_t> plaintext;
      if (key && iv && !key->empty() && !iv->empty()) {
        std::vector<uint8_t> pkt_iv = *iv;
        for (size_t i = 0; i < 8 && i < pkt_iv.size(); ++i) {
          pkt_iv[pkt_iv.size() - 1 - i] ^=
              (out.packet_number >> (i * 8)) & 0xFF;
        }
        if (!internal::DecryptData(*key, pkt_iv, payload_buf, plaintext)) {
          return false;
        }
      } else {
        plaintext = std::move(payload_buf);
      }

      // Deserialize frames from plaintext
      const uint8_t *p_buf = plaintext.data();
      size_t p_len = plaintext.size();
      size_t p_offset = 0;

      out.frames.clear();
      while (p_offset < p_len) {
        QuicFrame frame;
        if (!internal::DeserializeFrame(p_buf, p_len, p_offset, frame))
          return false;
        out.frames.push_back(std::move(frame));
      }
      return true;
    }
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
        max_recv_offset_(initial_recv_window),
        max_send_offset_(65536) {}

  uint64_t GetStreamId() const { return stream_id_; }

  StreamState GetState() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return state_;
  }

  uint64_t GetMaxSendOffset() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return max_send_offset_;
  }

  void SetMaxSendOffset(uint64_t max_offset) {
    std::lock_guard<std::mutex> lock(mtx_);
    max_send_offset_ = std::max(max_send_offset_, max_offset);
  }

  /**
   * @brief Appends data to the stream send buffer.
   */
  void AppendWriteData(const std::vector<uint8_t> &data, bool fin = false) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (state_ == StreamState::HalfClosedLocal ||
        state_ == StreamState::Closed) {
      return;
    }
    send_buffer_.insert(send_buffer_.end(), data.begin(), data.end());
    if (fin) {
      send_fin_pending_ = true;
    }
  }

  void AppendWriteData(const std::string &data, bool fin = false) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    AppendWriteData(bytes, fin);
  }

  /**
   * @brief Pulls frames up to allowed limit from the stream send buffer.
   */
  std::vector<StreamFrame> PullWriteFrames(uint64_t max_conn_allowed) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (state_ == StreamState::HalfClosedLocal ||
        state_ == StreamState::Closed) {
      return {};
    }

    uint64_t stream_allowed = 0;
    if (max_send_offset_ > send_offset_) {
      stream_allowed = max_send_offset_ - send_offset_;
    }
    uint64_t allowed = std::min(stream_allowed, max_conn_allowed);
    size_t pull_size =
        std::min(send_buffer_.size(), static_cast<size_t>(allowed));

    std::vector<StreamFrame> frames;
    const size_t max_frame_data = 1200;  // Leave room for headers in MTU
    size_t data_offset = 0;
    size_t remaining = pull_size;

    while (remaining > 0) {
      StreamFrame frame;
      frame.stream_id = stream_id_;
      frame.offset = send_offset_;

      size_t chunk = std::min(remaining, max_frame_data);
      frame.data.assign(send_buffer_.begin() + data_offset,
                        send_buffer_.begin() + data_offset + chunk);
      data_offset += chunk;
      remaining -= chunk;
      send_offset_ += chunk;

      frame.fin = false;
      frames.push_back(std::move(frame));
    }

    if (pull_size > 0) {
      send_buffer_.erase(send_buffer_.begin(),
                         send_buffer_.begin() + pull_size);
    }

    if (send_buffer_.empty() && send_fin_pending_) {
      if (frames.empty()) {
        StreamFrame frame;
        frame.stream_id = stream_id_;
        frame.offset = send_offset_;
        frame.fin = true;
        frames.push_back(std::move(frame));
      } else {
        frames.back().fin = true;
      }
      send_fin_pending_ = false;

      if (state_ == StreamState::HalfClosedRemote) {
        state_ = StreamState::Closed;
      } else {
        state_ = StreamState::HalfClosedLocal;
      }
    }

    return frames;
  }

  /**
   * @brief Writes data to the send buffer and immediately returns allowed
   * frames.
   */
  std::vector<StreamFrame> Write(const std::vector<uint8_t> &data,
                                 bool fin = false) {
    AppendWriteData(data, fin);
    return PullWriteFrames(std::numeric_limits<uint64_t>::max());
  }

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

  uint64_t GetMaxRecvOffset() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return max_recv_offset_;
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
  uint64_t max_send_offset_;
  std::vector<uint8_t> send_buffer_;
  bool send_fin_pending_ = false;

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
// Congestion Control
// ============================================================================

enum class CongestionControlAlgorithm { NewReno, Cubic, ConstantWindow };

struct LostPacketInfo {
  uint64_t packet_number;
  size_t packet_size;
  std::chrono::steady_clock::time_point send_time;
};

class CongestionController {
 public:
  virtual ~CongestionController() = default;
  virtual void OnPacketSent(uint64_t packet_number, size_t sent_bytes) = 0;
  virtual void OnPacketAcked(
      uint64_t packet_number, size_t acked_bytes,
      std::chrono::steady_clock::time_point send_time,
      std::chrono::steady_clock::time_point ack_time) = 0;
  virtual void OnPacketsLost(
      const std::vector<LostPacketInfo> &lost_packets,
      std::chrono::steady_clock::time_point loss_time) = 0;
  virtual bool CanSend(size_t next_packet_size) const = 0;
  virtual size_t GetCongestionWindow() const = 0;
  virtual size_t GetBytesInFlight() const = 0;
  virtual std::string GetName() const = 0;
};

class NewRenoCongestionController : public CongestionController {
 public:
  explicit NewRenoCongestionController(size_t max_datagram_size = 1200)
      : max_datagram_size_(max_datagram_size),
        cwnd_(10 * max_datagram_size),
        ssthresh_(std::numeric_limits<size_t>::max()),
        bytes_in_flight_(0),
        recovery_start_time_(std::chrono::steady_clock::time_point{}) {}

  void OnPacketSent(uint64_t, size_t sent_bytes) override {
    bytes_in_flight_ += sent_bytes;
  }

  void OnPacketAcked(uint64_t, size_t acked_bytes,
                     std::chrono::steady_clock::time_point send_time,
                     std::chrono::steady_clock::time_point ack_time) override {
    if (bytes_in_flight_ >= acked_bytes) {
      bytes_in_flight_ -= acked_bytes;
    } else {
      bytes_in_flight_ = 0;
    }

    if (send_time < recovery_start_time_) {
      // In recovery, do not grow window
      return;
    }

    if (cwnd_ < ssthresh_) {
      // Slow Start
      cwnd_ += acked_bytes;
    } else {
      // Congestion Avoidance
      cwnd_ += (max_datagram_size_ * acked_bytes) / cwnd_;
    }
  }

  void OnPacketsLost(const std::vector<LostPacketInfo> &lost_packets,
                     std::chrono::steady_clock::time_point loss_time) override {
    std::chrono::steady_clock::time_point max_send_time =
        std::chrono::steady_clock::time_point::min();
    for (const auto &pkt : lost_packets) {
      if (bytes_in_flight_ >= pkt.packet_size) {
        bytes_in_flight_ -= pkt.packet_size;
      } else {
        bytes_in_flight_ = 0;
      }
      if (pkt.send_time > max_send_time) {
        max_send_time = pkt.send_time;
      }
    }

    if (max_send_time >= recovery_start_time_) {
      recovery_start_time_ = loss_time;
      ssthresh_ = cwnd_ / 2;
      ssthresh_ = std::max(ssthresh_, 2 * max_datagram_size_);
      cwnd_ = ssthresh_;
    }
  }

  bool CanSend(size_t next_packet_size) const override {
    return bytes_in_flight_ + next_packet_size <= cwnd_;
  }

  size_t GetCongestionWindow() const override { return cwnd_; }
  size_t GetBytesInFlight() const override { return bytes_in_flight_; }
  std::string GetName() const override { return "NewReno"; }

 private:
  size_t max_datagram_size_;
  size_t cwnd_;
  size_t ssthresh_;
  size_t bytes_in_flight_;
  std::chrono::steady_clock::time_point recovery_start_time_;
};

class CubicCongestionController : public CongestionController {
 public:
  explicit CubicCongestionController(size_t max_datagram_size = 1200)
      : max_datagram_size_(max_datagram_size),
        cwnd_(10 * max_datagram_size),
        ssthresh_(std::numeric_limits<size_t>::max()),
        bytes_in_flight_(0),
        C_(0.4),
        beta_(0.7),
        W_max_(0.0),
        K_(0.0),
        epoch_start_time_(std::chrono::steady_clock::now()),
        recovery_start_time_(std::chrono::steady_clock::time_point{}) {}

  void OnPacketSent(uint64_t, size_t sent_bytes) override {
    bytes_in_flight_ += sent_bytes;
  }

  void OnPacketAcked(uint64_t, size_t acked_bytes,
                     std::chrono::steady_clock::time_point send_time,
                     std::chrono::steady_clock::time_point ack_time) override {
    if (bytes_in_flight_ >= acked_bytes) {
      bytes_in_flight_ -= acked_bytes;
    } else {
      bytes_in_flight_ = 0;
    }

    if (send_time < recovery_start_time_) {
      // In recovery, do not grow window
      return;
    }

    if (cwnd_ < ssthresh_) {
      // Slow Start
      cwnd_ += acked_bytes;
    } else {
      // Congestion Avoidance
      double t =
          std::chrono::duration<double>(ack_time - epoch_start_time_).count();
      double W_max_pkts = W_max_ / max_datagram_size_;

      double W_cubic_pkts = C_ * std::pow(t - K_, 3.0) + W_max_pkts;
      double W_cubic_bytes = W_cubic_pkts * max_datagram_size_;
      if (W_cubic_bytes < static_cast<double>(max_datagram_size_)) {
        W_cubic_bytes = static_cast<double>(max_datagram_size_);
      }

      size_t cubic_increment = 0;
      if (W_cubic_bytes > cwnd_) {
        cubic_increment =
            static_cast<size_t>((W_cubic_bytes - cwnd_) * acked_bytes / cwnd_);
      }

      size_t reno_increment = (max_datagram_size_ * acked_bytes) / cwnd_;

      cwnd_ += std::max(cubic_increment, reno_increment);
    }
  }

  void OnPacketsLost(const std::vector<LostPacketInfo> &lost_packets,
                     std::chrono::steady_clock::time_point loss_time) override {
    std::chrono::steady_clock::time_point max_send_time =
        std::chrono::steady_clock::time_point::min();
    for (const auto &pkt : lost_packets) {
      if (bytes_in_flight_ >= pkt.packet_size) {
        bytes_in_flight_ -= pkt.packet_size;
      } else {
        bytes_in_flight_ = 0;
      }
      if (pkt.send_time > max_send_time) {
        max_send_time = pkt.send_time;
      }
    }

    if (max_send_time >= recovery_start_time_) {
      recovery_start_time_ = loss_time;
      epoch_start_time_ = loss_time;

      W_max_ = static_cast<double>(cwnd_);
      if (W_max_ < 10.0 * max_datagram_size_) {
        W_max_ = 10.0 * max_datagram_size_;
      }

      ssthresh_ = static_cast<size_t>(W_max_ * beta_);
      ssthresh_ = std::max(ssthresh_, 2 * max_datagram_size_);
      cwnd_ = ssthresh_;

      double W_max_pkts = W_max_ / max_datagram_size_;
      K_ = std::cbrt((W_max_pkts * (1.0 - beta_)) / C_);
    }
  }

  bool CanSend(size_t next_packet_size) const override {
    return bytes_in_flight_ + next_packet_size <= cwnd_;
  }

  size_t GetCongestionWindow() const override { return cwnd_; }
  size_t GetBytesInFlight() const override { return bytes_in_flight_; }
  std::string GetName() const override { return "Cubic"; }

 private:
  size_t max_datagram_size_;
  size_t cwnd_;
  size_t ssthresh_;
  size_t bytes_in_flight_;
  double C_;
  double beta_;
  double W_max_;
  double K_;
  std::chrono::steady_clock::time_point epoch_start_time_;
  std::chrono::steady_clock::time_point recovery_start_time_;
};

class ConstantWindowCongestionController : public CongestionController {
 public:
  explicit ConstantWindowCongestionController(size_t max_datagram_size = 1200,
                                              size_t fixed_window = 1000 * 1200)
      : fixed_window_(fixed_window), bytes_in_flight_(0) {}

  void OnPacketSent(uint64_t, size_t sent_bytes) override {
    bytes_in_flight_ += sent_bytes;
  }

  void OnPacketAcked(uint64_t, size_t acked_bytes,
                     std::chrono::steady_clock::time_point,
                     std::chrono::steady_clock::time_point) override {
    if (bytes_in_flight_ >= acked_bytes) {
      bytes_in_flight_ -= acked_bytes;
    } else {
      bytes_in_flight_ = 0;
    }
  }

  void OnPacketsLost(const std::vector<LostPacketInfo> &lost_packets,
                     std::chrono::steady_clock::time_point) override {
    for (const auto &pkt : lost_packets) {
      if (bytes_in_flight_ >= pkt.packet_size) {
        bytes_in_flight_ -= pkt.packet_size;
      } else {
        bytes_in_flight_ = 0;
      }
    }
  }

  bool CanSend(size_t next_packet_size) const override {
    return bytes_in_flight_ + next_packet_size <= fixed_window_;
  }

  size_t GetCongestionWindow() const override { return fixed_window_; }
  size_t GetBytesInFlight() const override { return bytes_in_flight_; }
  std::string GetName() const override { return "ConstantWindow"; }

 private:
  size_t fixed_window_;
  size_t bytes_in_flight_;
};

inline std::unique_ptr<CongestionController> CreateCongestionController(
    CongestionControlAlgorithm algorithm, size_t max_datagram_size = 1200) {
  switch (algorithm) {
    case CongestionControlAlgorithm::NewReno:
      return std::make_unique<NewRenoCongestionController>(max_datagram_size);
    case CongestionControlAlgorithm::Cubic:
      return std::make_unique<CubicCongestionController>(max_datagram_size);
    case CongestionControlAlgorithm::ConstantWindow:
      return std::make_unique<ConstantWindowCongestionController>(
          max_datagram_size);
  }
  return std::make_unique<NewRenoCongestionController>(max_datagram_size);
}

// ============================================================================
// QUIC Connection
// ============================================================================

/**
 * @brief Represents a single QUIC connection.
 *
 * Manages streams, packet numbers, ACK tracking, and retransmission.
 */
struct QuicCryptoContext {
  SSL *ssl = nullptr;
  BIO *rbio = nullptr;
  BIO *wbio = nullptr;
  bool handshake_complete = false;

  // Initial keys
  std::vector<uint8_t> initial_read_key;
  std::vector<uint8_t> initial_read_iv;
  std::vector<uint8_t> initial_write_key;
  std::vector<uint8_t> initial_write_iv;

  // 1-RTT keys
  std::vector<uint8_t> read_key;
  std::vector<uint8_t> read_iv;
  std::vector<uint8_t> write_key;
  std::vector<uint8_t> write_iv;

  // 0-RTT keys
  std::vector<uint8_t> zerortt_read_key;
  std::vector<uint8_t> zerortt_read_iv;
  std::vector<uint8_t> zerortt_write_key;
  std::vector<uint8_t> zerortt_write_iv;

  QuicCryptoContext() = default;
  ~QuicCryptoContext() {
    if (ssl) SSL_free(ssl);
  }

  // Prevent copying/moving
  QuicCryptoContext(const QuicCryptoContext &) = delete;
  QuicCryptoContext &operator=(const QuicCryptoContext &) = delete;
};

class QuicConnection {
 public:
  QuicConnection(const ConnectionId &local_id, const ConnectionId &remote_id,
                 const cppudpnet::PeerAddress &peer, bool is_server,
                 SSL_CTX *custom_ctx = nullptr,
                 const ConnectionId &original_dest_id = ConnectionId{})
      : local_connection_id_(local_id),
        remote_connection_id_(remote_id),
        peer_(peer),
        is_server_(is_server) {
    crypto_ctx_ = std::make_shared<QuicCryptoContext>();
    SSL_CTX *ctx = custom_ctx ? custom_ctx : internal::GetSSLContext(is_server);
    crypto_ctx_->ssl = SSL_new(ctx);
    crypto_ctx_->rbio = BIO_new(BIO_s_mem());
    crypto_ctx_->wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(crypto_ctx_->ssl, crypto_ctx_->rbio, crypto_ctx_->wbio);
    if (is_server) {
      SSL_set_accept_state(crypto_ctx_->ssl);
    } else {
      SSL_set_connect_state(crypto_ctx_->ssl);
    }

    // Derive Initial keys from the client's original destination connection ID
    ConnectionId initial_id =
        original_dest_id.IsZero() ? remote_id : original_dest_id;
    internal::DeriveInitialKeys(
        initial_id, is_server, crypto_ctx_->initial_read_key,
        crypto_ctx_->initial_read_iv, crypto_ctx_->initial_write_key,
        crypto_ctx_->initial_write_iv);
    internal::DeriveZeroRTTKeys(
        initial_id, is_server, crypto_ctx_->zerortt_read_key,
        crypto_ctx_->zerortt_read_iv, crypto_ctx_->zerortt_write_key,
        crypto_ctx_->zerortt_write_iv);
    congestion_controller_ =
        CreateCongestionController(CongestionControlAlgorithm::NewReno);
  }

  ConnectionId GetLocalConnectionId() const { return local_connection_id_; }
  ConnectionId GetRemoteConnectionId() const { return remote_connection_id_; }
  void SetRemoteConnectionId(const ConnectionId &id) {
    std::lock_guard<std::mutex> lock(mtx_);
    remote_connection_id_ = id;
  }
  cppudpnet::PeerAddress GetPeer() const { return peer_; }

  void SetPeer(const cppudpnet::PeerAddress &peer) {
    std::lock_guard<std::mutex> lock(mtx_);
    peer_ = peer;
  }

  void InitiatePathValidation(const cppudpnet::PeerAddress &new_peer) {
    std::lock_guard<std::mutex> lock(mtx_);
    path_validated_ = false;
    candidate_peer_ = new_peer;
    for (int i = 0; i < 8; ++i) {
      pending_challenge_[i] = static_cast<uint8_t>(std::rand() & 0xFF);
    }
    challenge_pending_ = true;

    PathChallengeFrame challenge;
    std::memcpy(challenge.data, pending_challenge_, 8);

    std::vector<QuicFrame> frames;
    frames.push_back(std::move(challenge));
    pending_packets_.push_back(std::move(frames));
  }

  bool IsPathValidated() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return path_validated_;
  }

  void SetPathValidated(bool val) {
    std::lock_guard<std::mutex> lock(mtx_);
    path_validated_ = val;
  }

  cppudpnet::PeerAddress GetCandidatePeer() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return candidate_peer_;
  }

  void SetCandidatePeer(const cppudpnet::PeerAddress &peer) {
    std::lock_guard<std::mutex> lock(mtx_);
    candidate_peer_ = peer;
  }

  void GetPendingChallenge(uint8_t out[8]) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::memcpy(out, pending_challenge_, 8);
  }

  void SetPendingChallenge(const uint8_t in[8]) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::memcpy(pending_challenge_, in, 8);
    challenge_pending_ = true;
  }

  bool IsChallengePending() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return challenge_pending_;
  }

  void ClearPendingChallenge() {
    std::lock_guard<std::mutex> lock(mtx_);
    challenge_pending_ = false;
  }

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

  std::shared_ptr<QuicCryptoContext> GetCryptoContext() const {
    return crypto_ctx_;
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
  QuicPacket CreatePacket(std::vector<QuicFrame> frames,
                          uint8_t packet_type = 0) {
    std::lock_guard<std::mutex> lock(mtx_);
    QuicPacket pkt;
    pkt.packet_type = packet_type;
    pkt.connection_id = remote_connection_id_;
    pkt.source_connection_id = local_connection_id_;
    pkt.packet_number = next_packet_number_++;
    pkt.frames = std::move(frames);

    // Track sent packet for retransmission only if it is ack-eliciting
    bool ack_eliciting = false;
    if (pkt.frames.empty()) {
      ack_eliciting = true;
    } else {
      for (const auto &frame : pkt.frames) {
        if (!std::holds_alternative<AckFrame>(frame) &&
            !std::holds_alternative<ConnectionCloseFrame>(frame) &&
            !std::holds_alternative<PaddingFrame>(frame)) {
          ack_eliciting = true;
          break;
        }
      }
    }
    if (ack_eliciting) {
      SentPacketInfo info;
      info.packet_number = pkt.packet_number;
      info.send_time = std::chrono::steady_clock::now();
      info.frames = pkt.frames;
      info.packet_type = pkt.packet_type;
      sent_packets_[pkt.packet_number] = std::move(info);
    }

    return pkt;
  }

  /**
   * @brief Creates a handshake packet (ClientHello or ServerHello).
   */
  QuicPacket CreateHandshakePacket(
      const std::vector<uint8_t> &crypto_data = {}) {
    CryptoFrame cf;
    cf.offset = 0;
    cf.data = crypto_data;

    std::vector<QuicFrame> frames;
    frames.push_back(std::move(cf));
    return CreatePacket(std::move(frames), 1);  // 1 = Initial (Long Header)
  }

  std::vector<uint8_t> SerializePacket(const QuicPacket &pkt) {
    std::lock_guard<std::mutex> lock(mtx_);
    const std::vector<uint8_t> *write_key = nullptr;
    const std::vector<uint8_t> *write_iv = nullptr;
    if (crypto_ctx_) {
      if (pkt.packet_type == 1 || pkt.packet_type == 2) {
        write_key = &crypto_ctx_->initial_write_key;
        write_iv = &crypto_ctx_->initial_write_iv;
      } else if (pkt.packet_type == 3) {
        write_key = &crypto_ctx_->zerortt_write_key;
        write_iv = &crypto_ctx_->zerortt_write_iv;
      } else {
        if (crypto_ctx_->handshake_complete) {
          write_key = &crypto_ctx_->write_key;
          write_iv = &crypto_ctx_->write_iv;
        } else {
          write_key = &crypto_ctx_->initial_write_key;
          write_iv = &crypto_ctx_->initial_write_iv;
        }
      }
    }
    auto bytes = pkt.Serialize(write_key, write_iv);

    auto it = sent_packets_.find(pkt.packet_number);
    if (it != sent_packets_.end()) {
      it->second.packet_size = bytes.size();
      if (congestion_controller_) {
        congestion_controller_->OnPacketSent(pkt.packet_number, bytes.size());
      }
    }
    return bytes;
  }

  bool DeserializePacket(const std::vector<uint8_t> &data, QuicPacket &out) {
    std::lock_guard<std::mutex> lock(mtx_);
    const std::vector<uint8_t> *read_key = nullptr;
    const std::vector<uint8_t> *read_iv = nullptr;
    if (crypto_ctx_) {
      uint8_t packet_type = 0;
      if (!data.empty()) {
        uint8_t first = data[0];
        if (first & 0x80) {
          uint8_t type = (first >> 4) & 0x03;
          if (type == 0)
            packet_type = 1;
          else if (type == 2)
            packet_type = 2;
          else if (type == 1)
            packet_type = 3;
        }
      }
      if (packet_type == 1 || packet_type == 2) {
        read_key = &crypto_ctx_->initial_read_key;
        read_iv = &crypto_ctx_->initial_read_iv;
      } else if (packet_type == 3) {
        read_key = &crypto_ctx_->zerortt_read_key;
        read_iv = &crypto_ctx_->zerortt_read_iv;
      } else {
        if (crypto_ctx_->handshake_complete) {
          read_key = &crypto_ctx_->read_key;
          read_iv = &crypto_ctx_->read_iv;
        } else {
          read_key = &crypto_ctx_->initial_read_key;
          read_iv = &crypto_ctx_->initial_read_iv;
        }
      }
    }
    return QuicPacket::Deserialize(data, out, read_key, read_iv);
  }

  void ProcessCrypto(const std::vector<uint8_t> &in_data,
                     std::vector<uint8_t> &out_data) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!crypto_ctx_ || crypto_ctx_->handshake_complete) return;

    if (!in_data.empty()) {
      BIO_write(crypto_ctx_->rbio, in_data.data(), in_data.size());
    }

    int ret = SSL_do_handshake(crypto_ctx_->ssl);

    char buf[4096];
    while (true) {
      int bytes_read = BIO_read(crypto_ctx_->wbio, buf, sizeof(buf));
      if (bytes_read <= 0) break;
      out_data.insert(out_data.end(), buf, buf + bytes_read);
    }

    if (ret == 1) {
      crypto_ctx_->handshake_complete = true;
      ExtractKeys();
    }
  }

  void ExtractKeys() {
    crypto_ctx_->read_key.resize(16);
    crypto_ctx_->read_iv.resize(12);
    crypto_ctx_->write_key.resize(16);
    crypto_ctx_->write_iv.resize(12);

    const char *client_label = "EXPORTER-QUIC client";
    const char *server_label = "EXPORTER-QUIC server";

    std::vector<uint8_t> client_secret(32);
    std::vector<uint8_t> server_secret(32);

    SSL_export_keying_material(crypto_ctx_->ssl, client_secret.data(), 32,
                               client_label, strlen(client_label), nullptr, 0,
                               0);
    SSL_export_keying_material(crypto_ctx_->ssl, server_secret.data(), 32,
                               server_label, strlen(server_label), nullptr, 0,
                               0);

    if (is_server_) {
      crypto_ctx_->read_key =
          internal::HKDF_Expand_Label(client_secret, "quic key", {}, 16);
      crypto_ctx_->read_iv =
          internal::HKDF_Expand_Label(client_secret, "quic iv", {}, 12);
      crypto_ctx_->write_key =
          internal::HKDF_Expand_Label(server_secret, "quic key", {}, 16);
      crypto_ctx_->write_iv =
          internal::HKDF_Expand_Label(server_secret, "quic iv", {}, 12);
    } else {
      crypto_ctx_->write_key =
          internal::HKDF_Expand_Label(client_secret, "quic key", {}, 16);
      crypto_ctx_->write_iv =
          internal::HKDF_Expand_Label(client_secret, "quic iv", {}, 12);
      crypto_ctx_->read_key =
          internal::HKDF_Expand_Label(server_secret, "quic key", {}, 16);
      crypto_ctx_->read_iv =
          internal::HKDF_Expand_Label(server_secret, "quic iv", {}, 12);
    }
    internal::Log(LogSeverity::Info, "QuicConnection",
                  "Handshake complete, 1-RTT keys derived via HKDF.");
  }

  /**
   * @brief Processes a received ACK frame, removing acknowledged packets.
   * @return The number of newly acknowledged packets.
   */
  size_t ProcessAck(const AckFrame &ack) {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t acked = 0;
    auto now = std::chrono::steady_clock::now();
    for (auto pkt_num : ack.acknowledged_packets) {
      auto it = sent_packets_.find(pkt_num);
      if (it != sent_packets_.end()) {
        if (congestion_controller_) {
          congestion_controller_->OnPacketAcked(pkt_num, it->second.packet_size,
                                                it->second.send_time, now);
        }
        sent_packets_.erase(it);
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
    std::vector<LostPacketInfo> lost_infos;
    for (auto &[pkt_num, info] : sent_packets_) {
      if (now - info.send_time > timeout) {
        lost_packets.push_back(pkt_num);
        lost_infos.push_back({pkt_num, info.packet_size, info.send_time});
      }
    }

    if (congestion_controller_ && !lost_infos.empty()) {
      congestion_controller_->OnPacketsLost(lost_infos, now);
    }

    for (auto pkt_num : lost_packets) {
      auto it = sent_packets_.find(pkt_num);
      if (it != sent_packets_.end()) {
        // Create a new packet with the same frames
        QuicPacket pkt;
        pkt.connection_id = remote_connection_id_;
        pkt.packet_number = next_packet_number_++;
        pkt.frames = it->second.frames;
        pkt.packet_type = it->second.packet_type;

        // Track the new packet
        SentPacketInfo new_info;
        new_info.packet_number = pkt.packet_number;
        new_info.send_time = now;
        new_info.frames = pkt.frames;
        new_info.packet_size = it->second.packet_size;
        new_info.packet_type = pkt.packet_type;

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

  /**
   * @brief Sets the congestion control algorithm.
   */
  void SetCongestionControlAlgorithm(CongestionControlAlgorithm algorithm) {
    std::lock_guard<std::mutex> lock(mtx_);
    congestion_controller_ = CreateCongestionController(algorithm);
  }

  /**
   * @brief Returns the active congestion controller, or nullptr if none.
   */
  CongestionController *GetCongestionController() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return congestion_controller_.get();
  }

  /**
   * @brief Queue a list of frames to be sent as a packet once allowed by the
   * congestion controller.
   */
  void QueuePendingPacket(std::vector<QuicFrame> frames) {
    std::lock_guard<std::mutex> lock(mtx_);
    pending_packets_.push_back(std::move(frames));
  }

  /**
   * @brief Returns true if there are packets waiting to be sent in the queue.
   */
  bool HasPendingPackets() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return !pending_packets_.empty();
  }

  /**
   * @brief Pops the next pending packet's frames from the queue.
   */
  std::vector<QuicFrame> PopPendingPacket() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (pending_packets_.empty()) return {};
    auto frames = std::move(pending_packets_.front());
    pending_packets_.pop_front();
    return frames;
  }

  /**
   * @brief Checks if a packet of the specified size can be sent under
   * congestion control.
   */
  bool CanSend(size_t next_packet_size) const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!congestion_controller_) return true;
    return congestion_controller_->CanSend(next_packet_size);
  }

  uint64_t GetMaxSendData() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return max_send_data_;
  }

  void SetMaxSendData(uint64_t val) {
    std::lock_guard<std::mutex> lock(mtx_);
    max_send_data_ = std::max(max_send_data_, val);
  }

  void AddBytesRead(size_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_stream_bytes_read_ += bytes;
  }

  uint64_t GetMaxRecvData() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return 1048576 + total_stream_bytes_read_;
  }

  void SetAutoFlowControl(bool enable) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto_flow_control_ = enable;
  }

  bool IsAutoFlowControlEnabled() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return auto_flow_control_;
  }

  uint64_t GetTotalStreamBytesSent() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return total_stream_bytes_sent_;
  }

  void AddTotalStreamBytesSent(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_stream_bytes_sent_ += bytes;
  }

  void GenerateStreamPackets() {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto &[stream_id, stream] : streams_) {
      while (true) {
        uint64_t conn_allowed = 0;
        if (max_send_data_ > total_stream_bytes_sent_) {
          conn_allowed = max_send_data_ - total_stream_bytes_sent_;
        }
        if (conn_allowed == 0) {
          break;
        }

        auto frames = stream->PullWriteFrames(conn_allowed);
        if (frames.empty()) {
          break;
        }

        for (auto &sf : frames) {
          total_stream_bytes_sent_ += sf.data.size();
          std::vector<QuicFrame> quic_frames;
          quic_frames.push_back(std::move(sf));
          pending_packets_.push_back(std::move(quic_frames));
        }
      }
    }
  }

 private:
  uint64_t max_send_data_ = 1048576;  // 1MB initial limit
  uint64_t total_stream_bytes_sent_ = 0;
  uint64_t total_stream_bytes_read_ = 0;
  bool auto_flow_control_ = true;
  struct SentPacketInfo {
    uint64_t packet_number = 0;
    std::chrono::steady_clock::time_point send_time;
    std::vector<QuicFrame> frames;
    size_t packet_size = 0;
    uint8_t packet_type = 0;
  };

  ConnectionId local_connection_id_;
  ConnectionId remote_connection_id_;
  cppudpnet::PeerAddress peer_;
  bool path_validated_ = true;
  cppudpnet::PeerAddress candidate_peer_;
  uint8_t pending_challenge_[8] = {0};
  bool challenge_pending_ = false;
  bool is_server_;

  std::shared_ptr<QuicCryptoContext> crypto_ctx_;

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

  std::unique_ptr<CongestionController> congestion_controller_;
  std::deque<std::vector<QuicFrame>> pending_packets_;
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
      : listener_(port, bind_address) {
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
    if (!internal::GenerateSelfSignedCert(ssl_ctx_)) {
      internal::Log(LogSeverity::Error, "QuicServer",
                    "Failed to generate self-signed certificate");
    }
  }

  /**
   * @brief Allows developer to configure custom certificate and private key.
   */
  void SetCertificate(const std::string &cert_path,
                      const std::string &key_path) {
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx_, cert_path.c_str()) <= 0) {
      throw std::runtime_error("Failed to load certificate chain file: " +
                               cert_path);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_path.c_str(),
                                    SSL_FILETYPE_PEM) <= 0) {
      throw std::runtime_error("Failed to load private key file: " + key_path);
    }
    if (SSL_CTX_check_private_key(ssl_ctx_) <= 0) {
      throw std::runtime_error(
          "Private key does not match the certificate public key");
    }
  }

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
   * @brief Returns the number of active connections.
   */
  size_t GetActiveConnectionCount() const {
    std::lock_guard<std::mutex> lock(connections_mtx_);
    return connections_.size();
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
      auto packets = QuicPacket::SplitCoalescedPackets(data);
      for (const auto &pkt_bytes : packets) {
        HandleIncomingPacket(peer, pkt_bytes);
      }
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
          auto bytes = conn->SerializePacket(close_pkt);
          listener_.Send(conn->GetPeer(), bytes);
          conn->SetState(ConnectionState::Closed);
        }
      }
      connections_.clear();
    }

    listener_.Stop();
    internal::Log(LogSeverity::Info, "QuicServer", "Stopped");
  }

  ~QuicServer() {
    Stop();
    if (ssl_ctx_) {
      SSL_CTX_free(ssl_ctx_);
      ssl_ctx_ = nullptr;
    }
  }

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
  void SendPendingPackets(std::shared_ptr<QuicConnection> conn) {
    if (!conn) return;
    while (conn->HasPendingPackets() && conn->CanSend(1200)) {
      auto frames = conn->PopPendingPacket();
      uint8_t pkt_type =
          (conn->GetState() == ConnectionState::Handshaking) ? 3 : 0;
      auto pkt = conn->CreatePacket(std::move(frames), pkt_type);
      auto bytes = conn->SerializePacket(pkt);
      conn->AddBytesSent(bytes.size());

      cppudpnet::PeerAddress dest = conn->GetPeer();
      if (!conn->IsPathValidated() && conn->IsChallengePending()) {
        dest = conn->GetCandidatePeer();
      }
      listener_.Send(dest, bytes);
    }
  }

  void SendOnStream(std::shared_ptr<QuicConnection> conn, uint64_t stream_id,
                    const std::vector<uint8_t> &data, bool fin = false) {
    auto stream = conn->GetOrCreateStream(stream_id);
    stream->AppendWriteData(data, fin);
    conn->GenerateStreamPackets();
    SendPendingPackets(conn);
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
   * @brief Sets the congestion control algorithm to use for new connections.
   */
  void SetCongestionControlAlgorithm(CongestionControlAlgorithm algorithm) {
    cc_algorithm_ = algorithm;
  }

  void SetAutoFlowControl(bool enable) { auto_flow_control_ = enable; }

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
    ConnectionId conn_id;
    if (!QuicPacket::PeekConnectionId(data, conn_id)) {
      return;
    }

    std::shared_ptr<QuicConnection> conn;
    {
      std::lock_guard<std::mutex> lock(connections_mtx_);
      for (auto &[id, c] : connections_) {
        if (c->GetLocalConnectionId() == conn_id ||
            c->GetRemoteConnectionId() == conn_id) {
          conn = c;
          break;
        }
      }
    }

    QuicPacket pkt;
    if (conn) {
      if (!conn->DeserializePacket(data, pkt)) {
        internal::Log(LogSeverity::Warn, "QuicServer",
                      "Failed to deserialize packet from " + peer.ToString());
        return;
      }
    } else {
      bool is_initial = false;
      if (!data.empty() && (data[0] & 0x80)) {
        uint8_t type = (data[0] >> 4) & 0x03;
        if (type == 0) is_initial = true;
      }

      if (!is_initial) {
        uint8_t token[16];
        internal::DeriveStatelessResetToken(conn_id, token);

        std::vector<uint8_t> reset_pkt(40);
        reset_pkt[0] = 0x43;
        for (size_t i = 1; i < 24; ++i) {
          reset_pkt[i] = static_cast<uint8_t>(std::rand() & 0xFF);
        }
        std::memcpy(reset_pkt.data() + 24, token, 16);

        listener_.Send(peer, reset_pkt);
        internal::Log(
            LogSeverity::Info, "QuicServer",
            "Sent Stateless Reset to unknown client " + peer.ToString());
        return;
      }

      // Derive Initial keys to decrypt ClientHello
      std::vector<uint8_t> temp_read_key;
      std::vector<uint8_t> temp_read_iv;
      std::vector<uint8_t> temp_write_key;
      std::vector<uint8_t> temp_write_iv;
      internal::DeriveInitialKeys(conn_id, true, temp_read_key, temp_read_iv,
                                  temp_write_key, temp_write_iv);

      if (!QuicPacket::Deserialize(data, pkt, &temp_read_key, &temp_read_iv)) {
        internal::Log(
            LogSeverity::Warn, "QuicServer",
            "Failed to deserialize Initial packet from " + peer.ToString());
        return;
      }
    }

    // Process frames
    for (const auto &frame : pkt.frames) {
      std::visit(
          [this, &peer, &pkt, &conn, &conn_id](auto &&f) {
            using T = std::decay_t<decltype(f)>;

            if constexpr (std::is_same_v<T, CryptoFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                std::vector<uint8_t> crypto_out;
                conn->ProcessCrypto(f.data, crypto_out);

                auto crypto_ctx = conn->GetCryptoContext();
                if (crypto_ctx && crypto_ctx->handshake_complete &&
                    conn->GetState() == ConnectionState::Handshaking) {
                  conn->SetState(ConnectionState::Connected);
                  internal::Log(LogSeverity::Info, "QuicServer",
                                "Handshake complete. Server Connected: " +
                                    conn->GetLocalConnectionId().ToHex());
                  event_broker_.Publish<ConnectionEvent>(
                      "connection_events", {conn->GetLocalConnectionId(), peer,
                                            ConnectionState::Connected});
                  if (connection_handler_) {
                    connection_handler_(conn);
                  }
                }
              } else {
                // If conn doesn't exist, this is ClientHello (represented in
                // CryptoFrame)
                conn = HandleClientHello(peer, conn_id,
                                         pkt.source_connection_id, f);
                if (conn) {
                  conn->RecordReceivedPacket(pkt.packet_number);
                }
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
                SendPendingPackets(conn);
              }
            } else if constexpr (std::is_same_v<T, PingFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
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
            } else if constexpr (std::is_same_v<T, PathChallengeFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                PathResponseFrame resp;
                std::memcpy(resp.data, f.data, 8);
                auto pkt_out = conn->CreatePacket({resp});
                auto bytes = conn->SerializePacket(pkt_out);
                conn->AddBytesSent(bytes.size());
                listener_.Send(peer, bytes);
              }
            } else if constexpr (std::is_same_v<T, PathResponseFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                uint8_t pending[8];
                conn->GetPendingChallenge(pending);
                if (conn->IsChallengePending() &&
                    std::memcmp(pending, f.data, 8) == 0) {
                  conn->ClearPendingChallenge();
                  conn->SetPathValidated(true);
                  conn->SetPeer(peer);
                }
              }
            } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                auto stream = conn->GetStream(f.stream_id);
                if (stream) {
                  stream->Reset(f.error_code);
                  ResetStreamFrame reset;
                  reset.stream_id = f.stream_id;
                  reset.error_code = f.error_code;
                  reset.final_size = stream->GetSendOffset();
                  auto pkt_out = conn->CreatePacket({reset});
                  auto bytes = conn->SerializePacket(pkt_out);
                  conn->AddBytesSent(bytes.size());
                  listener_.Send(conn->GetPeer(), bytes);
                }
              }
            } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                conn->SetMaxSendData(f.max_data);
                conn->GenerateStreamPackets();
                SendPendingPackets(conn);
              }
            } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
              if (conn) {
                conn->Touch();
                conn->RecordReceivedPacket(pkt.packet_number);
                auto stream = conn->GetStream(f.stream_id);
                if (stream) {
                  stream->SetMaxSendOffset(f.max_stream_data);
                  conn->GenerateStreamPackets();
                  SendPendingPackets(conn);
                }
              }
            }
          },
          frame);
    }
  }

  std::shared_ptr<QuicConnection> HandleClientHello(
      const cppudpnet::PeerAddress &peer, const ConnectionId &dest_id,
      const ConnectionId &src_id, const CryptoFrame &cf) {
    auto local_id = internal::GenerateConnectionId();
    auto remote_id = src_id;

    // RFC 9001 §5.2: initial keys must be derived from the client's original
    // Destination Connection ID (dest_id), not from the server's generated IDs.
    auto conn = std::make_shared<QuicConnection>(local_id, remote_id, peer,
                                                 true, ssl_ctx_, dest_id);
    conn->SetCongestionControlAlgorithm(cc_algorithm_);
    conn->SetAutoFlowControl(auto_flow_control_);
    conn->SetState(ConnectionState::Handshaking);

    {
      std::lock_guard<std::mutex> lock(connections_mtx_);
      connections_[local_id] = conn;
    }

    std::vector<uint8_t> crypto_out;
    conn->ProcessCrypto(cf.data, crypto_out);
    auto server_hello = conn->CreateHandshakePacket(crypto_out);
    auto bytes = conn->SerializePacket(server_hello);
    conn->AddBytesSent(bytes.size());
    listener_.Send(peer, bytes);

    internal::Log(LogSeverity::Info, "QuicServer",
                  "New handshaking connection from " + peer.ToString() + " [" +
                      local_id.ToHex() + "]");
    return conn;
  }

  void HandleStreamFrame(std::shared_ptr<QuicConnection> conn,
                         const StreamFrame &frame) {
    auto stream = conn->GetOrCreateStream(frame.stream_id);
    bool ok = stream->OnStreamFrame(frame);

    // Send ACK
    SendAck(conn);

    if (stream_data_handler_) {
      stream_data_handler_(conn, frame.stream_id, frame.data, frame.fin);
    }

    if (ok && conn->IsAutoFlowControlEnabled()) {
      stream->Read(0);
      conn->AddBytesRead(frame.data.size());
      MaxStreamDataFrame max_stream;
      max_stream.stream_id = frame.stream_id;
      max_stream.max_stream_data = stream->GetMaxRecvOffset();

      MaxDataFrame max_data;
      max_data.max_data = conn->GetMaxRecvData();

      std::vector<QuicFrame> frames;
      frames.push_back(std::move(max_stream));
      frames.push_back(std::move(max_data));
      auto pkt = conn->CreatePacket(std::move(frames));
      auto bytes = conn->SerializePacket(pkt);
      conn->AddBytesSent(bytes.size());
      listener_.Send(conn->GetPeer(), bytes);
    }
  }

  void SendAck(std::shared_ptr<QuicConnection> conn) {
    auto ack = conn->GenerateAck();
    std::vector<QuicFrame> frames;
    frames.push_back(std::move(ack));
    auto pkt = conn->CreatePacket(std::move(frames));
    auto bytes = conn->SerializePacket(pkt);
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
        if (conn->GetState() != ConnectionState::Connected &&
            conn->GetState() != ConnectionState::Handshaking)
          continue;

        // Check idle timeout
        if (conn->GetState() == ConnectionState::Connected &&
            conn->IsIdle(idle_timeout_)) {
          auto close_pkt = conn->CreateClosePacket(0, "Idle timeout");
          auto bytes = conn->SerializePacket(close_pkt);
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
          auto bytes = conn->SerializePacket(pkt);
          conn->AddBytesSent(bytes.size());
          listener_.Send(conn->GetPeer(), bytes);
        }
      }
    }
  }

  SSL_CTX *ssl_ctx_ = nullptr;
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
  CongestionControlAlgorithm cc_algorithm_ =
      CongestionControlAlgorithm::NewReno;
  bool auto_flow_control_ = true;
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
  QuicClient() {
    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
    // Accept self-signed server certificates by default. Developers can supply
    // their own verified CA store via SSL_CTX_load_verify_locations if needed.
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
  }

  /**
   * @brief Configures whether the client accepts self-signed server
   * certificates.
   *
   * By default, self-signed certificates are allowed (allow = true). Set to
   * false to enforce verification of peer certificates.
   */
  void SetAllowSelfSigned(bool allow) {
    if (allow) {
      SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
    } else {
      SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
    }
  }

  void SetCertificate(const std::string &cert_path,
                      const std::string &key_path) {
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx_, cert_path.c_str()) <= 0) {
      throw std::runtime_error("Failed to load certificate chain file: " +
                               cert_path);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_path.c_str(),
                                    SSL_FILETYPE_PEM) <= 0) {
      throw std::runtime_error("Failed to load private key file: " + key_path);
    }
    if (SSL_CTX_check_private_key(ssl_ctx_) <= 0) {
      throw std::runtime_error(
          "Private key does not match the certificate public key");
    }
  }

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
      auto packets = QuicPacket::SplitCoalescedPackets(data);
      for (const auto &pkt_bytes : packets) {
        HandleIncomingPacket(peer, pkt_bytes);
      }
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
      auto bytes = connection_->SerializePacket(close_pkt);
      sender_.Send(server_address_, bytes);
      connection_->SetState(ConnectionState::Closed);
    }

    sender_.Stop();
    connection_.reset();
    internal::Log(LogSeverity::Info, "QuicClient", "Stopped");
  }

  ~QuicClient() {
    Stop();
    if (ssl_ctx_) {
      SSL_CTX_free(ssl_ctx_);
      ssl_ctx_ = nullptr;
    }
  }

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
    auto remote_id = internal::GenerateConnectionId();  // Generate randomly for
                                                        // Initial keys!

    connection_ = std::make_shared<QuicConnection>(
        local_id, remote_id, server_address_, false, ssl_ctx_);
    connection_->SetCongestionControlAlgorithm(cc_algorithm_);
    connection_->SetAutoFlowControl(auto_flow_control_);
    connection_->SetState(ConnectionState::Handshaking);

    std::vector<uint8_t> crypto_out;
    connection_->ProcessCrypto({}, crypto_out);
    auto pkt = connection_->CreateHandshakePacket(crypto_out);
    auto bytes = connection_->SerializePacket(pkt);
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
    auto bytes = connection_->SerializePacket(close_pkt);
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
  /**
   * @brief Sets the congestion control algorithm to use for the connection.
   */
  void SetCongestionControlAlgorithm(CongestionControlAlgorithm algorithm) {
    cc_algorithm_ = algorithm;
    if (connection_) {
      connection_->SetCongestionControlAlgorithm(algorithm);
    }
  }

  void SetAutoFlowControl(bool enable) {
    auto_flow_control_ = enable;
    if (connection_) {
      connection_->SetAutoFlowControl(enable);
    }
  }

  void SendPendingPackets() {
    if (!connection_) return;
    while (connection_->HasPendingPackets() && connection_->CanSend(1200)) {
      auto frames = connection_->PopPendingPacket();
      uint8_t pkt_type =
          (connection_->GetState() == ConnectionState::Handshaking) ? 3 : 0;
      auto pkt = connection_->CreatePacket(std::move(frames), pkt_type);
      auto bytes = connection_->SerializePacket(pkt);
      connection_->AddBytesSent(bytes.size());

      cppudpnet::PeerAddress dest = server_address_;
      if (!connection_->IsPathValidated() &&
          connection_->IsChallengePending()) {
        dest = connection_->GetCandidatePeer();
      }
      sender_.Send(dest, bytes);
    }
  }

  void SendOnStream(uint64_t stream_id, const std::vector<uint8_t> &data,
                    bool fin = false) {
    if (!connection_ ||
        (connection_->GetState() != ConnectionState::Connected &&
         connection_->GetState() != ConnectionState::Handshaking)) {
      return;
    }

    auto stream = connection_->GetOrCreateStream(stream_id);
    stream->AppendWriteData(data, fin);
    connection_->GenerateStreamPackets();
    SendPendingPackets();
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
  void HandleIncomingPacket(
      const cppudpnet::PeerAddress &peer,
      const std::vector<std::vector<uint8_t>>::value_type &data) {
    ConnectionId conn_id;
    if (!QuicPacket::PeekConnectionId(data, conn_id)) {
      return;
    }

    QuicPacket pkt;
    if (connection_) {
      if (!connection_->DeserializePacket(data, pkt)) {
        if (data.size() >= 21) {
          uint8_t expected_token[16];
          internal::DeriveStatelessResetToken(
              connection_->GetRemoteConnectionId(), expected_token);
          if (std::memcmp(data.data() + data.size() - 16, expected_token, 16) ==
              0) {
            internal::Log(
                LogSeverity::Info, "QuicClient",
                "Stateless Reset received from server! Closing connection.");
            connection_->SetState(ConnectionState::Closed);
            return;
          }
        }
        internal::Log(LogSeverity::Warn, "QuicClient",
                      "Failed to deserialize packet from server");
        return;
      }
    } else {
      // Derive Initial keys to decrypt Server Initial packet
      std::vector<uint8_t> temp_read_key;
      std::vector<uint8_t> temp_read_iv;
      std::vector<uint8_t> temp_write_key;
      std::vector<uint8_t> temp_write_iv;
      internal::DeriveInitialKeys(conn_id, false, temp_read_key, temp_read_iv,
                                  temp_write_key, temp_write_iv);

      if (!QuicPacket::Deserialize(data, pkt, &temp_read_key, &temp_read_iv)) {
        internal::Log(LogSeverity::Warn, "QuicClient",
                      "Failed to deserialize Initial packet from server");
        return;
      }
    }

    for (const auto &frame : pkt.frames) {
      std::visit(
          [this, &pkt, &peer](auto &&f) {
            using T = std::decay_t<decltype(f)>;

            if constexpr (std::is_same_v<T, CryptoFrame>) {
              if (connection_) {
                connection_->RecordReceivedPacket(pkt.packet_number);
                // Server source connection ID is updated in the connection!
                connection_->SetRemoteConnectionId(pkt.source_connection_id);

                std::vector<uint8_t> crypto_out;
                connection_->ProcessCrypto(f.data, crypto_out);
                if (!crypto_out.empty()) {
                  auto pkt_out = connection_->CreateHandshakePacket(crypto_out);
                  auto bytes = connection_->SerializePacket(pkt_out);
                  connection_->AddBytesSent(bytes.size());
                  sender_.Send(server_address_, bytes);
                }

                auto crypto_ctx = connection_->GetCryptoContext();
                if (crypto_ctx && crypto_ctx->handshake_complete &&
                    connection_->GetState() == ConnectionState::Handshaking) {
                  connection_->SetState(ConnectionState::Connected);
                  internal::Log(LogSeverity::Info, "QuicClient",
                                "Handshake complete. Connected to server");
                }
              }
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                connection_->AddBytesReceived(f.data.size());

                auto stream = connection_->GetOrCreateStream(f.stream_id);
                bool ok = stream->OnStreamFrame(f);

                // Send ACK
                SendAck();

                if (stream_data_handler_) {
                  stream_data_handler_(f.stream_id, f.data, f.fin);
                }

                if (ok && connection_->IsAutoFlowControlEnabled()) {
                  stream->Read(0);
                  connection_->AddBytesRead(f.data.size());
                  MaxStreamDataFrame max_stream;
                  max_stream.stream_id = f.stream_id;
                  max_stream.max_stream_data = stream->GetMaxRecvOffset();

                  MaxDataFrame max_data;
                  max_data.max_data = connection_->GetMaxRecvData();

                  std::vector<QuicFrame> frames;
                  frames.push_back(std::move(max_stream));
                  frames.push_back(std::move(max_data));
                  auto pkt_out = connection_->CreatePacket(std::move(frames));
                  auto bytes = connection_->SerializePacket(pkt_out);
                  connection_->AddBytesSent(bytes.size());
                  sender_.Send(server_address_, bytes);
                }
              }
            } else if constexpr (std::is_same_v<T, AckFrame>) {
              if (connection_) {
                connection_->ProcessAck(f);
                SendPendingPackets();
              }
            } else if constexpr (std::is_same_v<T, PingFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                SendAck();
              }
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
              if (connection_) {
                connection_->SetState(ConnectionState::Closed);
                internal::Log(LogSeverity::Info, "QuicClient",
                              "Connection closed by server: " + f.reason);
              }
            } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
              if (connection_) {
                auto stream = connection_->GetStream(f.stream_id);
                if (stream) {
                  stream->Reset(f.error_code);
                }
              }
            } else if constexpr (std::is_same_v<T, PathChallengeFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                PathResponseFrame resp;
                std::memcpy(resp.data, f.data, 8);
                auto pkt_out = connection_->CreatePacket({resp});
                auto bytes = connection_->SerializePacket(pkt_out);
                connection_->AddBytesSent(bytes.size());
                sender_.Send(peer, bytes);
              }
            } else if constexpr (std::is_same_v<T, PathResponseFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                uint8_t pending[8];
                connection_->GetPendingChallenge(pending);
                if (connection_->IsChallengePending() &&
                    std::memcmp(pending, f.data, 8) == 0) {
                  connection_->ClearPendingChallenge();
                  connection_->SetPathValidated(true);
                  connection_->SetPeer(peer);
                }
              }
            } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                auto stream = connection_->GetStream(f.stream_id);
                if (stream) {
                  stream->Reset(f.error_code);
                  ResetStreamFrame reset;
                  reset.stream_id = f.stream_id;
                  reset.error_code = f.error_code;
                  reset.final_size = stream->GetSendOffset();
                  auto pkt_out = connection_->CreatePacket({reset});
                  auto bytes = connection_->SerializePacket(pkt_out);
                  connection_->AddBytesSent(bytes.size());
                  sender_.Send(server_address_, bytes);
                }
              }
            } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                connection_->SetMaxSendData(f.max_data);
                connection_->GenerateStreamPackets();
                SendPendingPackets();
              }
            } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                auto stream = connection_->GetStream(f.stream_id);
                if (stream) {
                  stream->SetMaxSendOffset(f.max_stream_data);
                  connection_->GenerateStreamPackets();
                  SendPendingPackets();
                }
              }
            } else if constexpr (std::is_same_v<T, HandshakeDoneFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->RecordReceivedPacket(pkt.packet_number);
                if (connection_->GetState() == ConnectionState::Handshaking) {
                  connection_->SetState(ConnectionState::Connected);
                  internal::Log(
                      LogSeverity::Info, "QuicClient",
                      "Handshake confirmed via HANDSHAKE_DONE frame.");
                }
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
    auto bytes = connection_->SerializePacket(pkt);
    connection_->AddBytesSent(bytes.size());
    sender_.Send(server_address_, bytes);
  }

  void MaintenanceLoop() {
    while (running_.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      if (!connection_ ||
          (connection_->GetState() != ConnectionState::Connected &&
           connection_->GetState() != ConnectionState::Handshaking)) {
        continue;
      }

      // Process retransmissions
      auto retransmits = connection_->GetRetransmissions();
      for (auto &pkt : retransmits) {
        auto bytes = connection_->SerializePacket(pkt);
        connection_->AddBytesSent(bytes.size());
        sender_.Send(server_address_, bytes);
      }
    }
  }

  SSL_CTX *ssl_ctx_ = nullptr;
  cppudpnet::UdpSender sender_;

  std::atomic<bool> running_{false};
  std::thread maintenance_thread_;

  cppudpnet::PeerAddress server_address_;
  std::shared_ptr<QuicConnection> connection_;

  std::function<void(uint64_t, const std::vector<uint8_t> &, bool)>
      stream_data_handler_;
  std::function<void(int, const std::string &)> error_handler_;

  CongestionControlAlgorithm cc_algorithm_ =
      CongestionControlAlgorithm::NewReno;
  bool auto_flow_control_ = true;
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
