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
#include <string>
#include <thread>
#include <unordered_map>
#include <variant>
#include <vector>

#include "cppudpnet.hpp"
#include "cpppubsub.hpp"
#include "cppasyncworker.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

namespace cppquic {
constexpr int VERSION_MAJOR = 1;
constexpr int VERSION_MINOR = 7;
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

/**
 * @brief Performs a high-precision, CPU-friendly yield sleep until a target
 * time point is reached. Helpful for sub-millisecond pacing delays.
 */
inline void PreciseSleepUntil(std::chrono::steady_clock::time_point target) {
  while (std::chrono::steady_clock::now() < target) {
    std::this_thread::yield();
  }
}

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
                        std::vector<uint8_t> &ciphertext_out,
                        const std::vector<uint8_t> &aad = {}) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  const EVP_CIPHER *cipher =
      (key.size() == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
  if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
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

  if (!aad.empty()) {
    int outlen = 0;
    if (1 != EVP_EncryptUpdate(ctx, NULL, &outlen, aad.data(), aad.size())) {
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
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
                        std::vector<uint8_t> &plaintext_out,
                        const std::vector<uint8_t> &aad = {}) {
  if (ciphertext_with_tag.size() < 16) return false;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  const EVP_CIPHER *cipher =
      (key.size() == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
  if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
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

  if (!aad.empty()) {
    int outlen = 0;
    if (1 != EVP_DecryptUpdate(ctx, NULL, &outlen, aad.data(), aad.size())) {
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
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
  const EVP_MD *md = (prk.size() == 48) ? EVP_sha384() : EVP_sha256();
  size_t hash_len = (prk.size() == 48) ? 48 : 32;
  while (okm.size() < L) {
    std::vector<uint8_t> input = T;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(counter);

    std::vector<uint8_t> tmp(hash_len);
    unsigned int tmp_len = hash_len;
    HMAC(md, prk.data(), prk.size(), input.data(), input.size(), tmp.data(),
         &tmp_len);
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

inline std::vector<uint8_t> HKDF_Expand_Label_QUIC(
    const std::vector<uint8_t> &secret, const std::string &label,
    const std::vector<uint8_t> &context, size_t length) {
  std::string full_label = "tls13 quic " + label;
  std::vector<uint8_t> hkdf_label;
  hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(length & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
  hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());
  hkdf_label.push_back(static_cast<uint8_t>(context.size()));
  hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());
  return HKDF_Expand(secret, hkdf_label, length);
}

}  // namespace internal
class QuicConnection;
namespace internal {
inline void QuicKeylogCallback(const SSL *ssl, const char *line);

inline std::vector<uint8_t> HexToBytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    if (i + 1 < hex.size()) {
      std::string byteString = hex.substr(i, 2);
      uint8_t byte =
          static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
      bytes.push_back(byte);
    }
  }
  return bytes;
}

inline bool ComputeHPMask(const std::vector<uint8_t> &hp_key,
                          const uint8_t *sample, uint8_t *mask_out) {
  if (hp_key.size() < 16) return false;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  const EVP_CIPHER *cipher =
      (hp_key.size() == 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
  if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, hp_key.data(), NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  int out_len = 0;
  if (1 != EVP_EncryptUpdate(ctx, mask_out, &out_len, sample, 16)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  EVP_CIPHER_CTX_free(ctx);
  return true;
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
 * @brief A variable-length QUIC connection identifier (up to 20 bytes).
 */
struct ConnectionId {
  uint8_t data[20] = {0};
  uint8_t length = 8;

  bool operator==(const ConnectionId &other) const {
    if (length != other.length) return false;
    return std::memcmp(data, other.data, length) == 0;
  }

  bool operator!=(const ConnectionId &other) const { return !(*this == other); }

  bool IsZero() const {
    for (int i = 0; i < length; ++i) {
      if (data[i] != 0) return false;
    }
    return true;
  }

  std::string ToHex() const {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (int i = 0; i < length; ++i) {
      result += hex_chars[(data[i] >> 4) & 0x0F];
      result += hex_chars[data[i] & 0x0F];
    }
    return result;
  }

  /**
   * @brief Serializes this ConnectionId into the end of a byte vector.
   */
  void Serialize(std::vector<uint8_t> &buf) const {
    buf.insert(buf.end(), data, data + length);
  }

  /**
   * @brief Deserializes a ConnectionId from a buffer at the given offset.
   * @return true on success, false if not enough bytes remain.
   */
  static bool Deserialize(const uint8_t *buf, size_t len, size_t &offset,
                          ConnectionId &out, uint8_t expected_len = 8) {
    if (offset + expected_len > len) return false;
    std::memcpy(out.data, buf + offset, expected_len);
    out.length = expected_len;
    offset += expected_len;
    return true;
  }
};

/**
 * @brief Hash function for ConnectionId.
 */
struct ConnectionIdHash {
  size_t operator()(const ConnectionId &id) const {
    size_t hash = 0;
    for (int i = 0; i < id.length; ++i) {
      hash ^= std::hash<uint8_t>{}(id.data[i]) << ((i % 8) * 4);
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
  CONNECTION_CLOSE = 0x1c,
  CONNECTION_CLOSE_APP = 0x1d,
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

          std::vector<uint64_t> pkts = f.acknowledged_packets;
          std::sort(pkts.begin(), pkts.end(), std::greater<uint64_t>());

          uint64_t first_ack_range = 0;
          size_t idx = 1;
          while (idx < pkts.size() && pkts[idx] == pkts[idx - 1] - 1) {
            first_ack_range++;
            idx++;
          }

          struct AckRange {
            uint64_t gap;
            uint64_t length;
          };
          std::vector<AckRange> ranges;

          while (idx < pkts.size()) {
            uint64_t gap = (pkts[idx - 1] - pkts[idx]) - 2;
            uint64_t length = 0;
            idx++;
            while (idx < pkts.size() && pkts[idx] == pkts[idx - 1] - 1) {
              length++;
              idx++;
            }
            ranges.push_back({gap, length});
          }

          WriteVarInt(buf, ranges.size());
          WriteVarInt(buf, first_ack_range);
          for (const auto &r : ranges) {
            WriteVarInt(buf, r.gap);
            WriteVarInt(buf, r.length);
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

      uint64_t ack_range_count = 0;
      if (!ReadVarInt(buf, len, offset, ack_range_count)) return false;

      uint64_t first_ack_range = 0;
      if (!ReadVarInt(buf, len, offset, first_ack_range)) return false;

      if (f.largest_acknowledged < first_ack_range) return false;

      uint64_t current_packet = f.largest_acknowledged;
      for (uint64_t i = 0; i <= first_ack_range; ++i) {
        f.acknowledged_packets.push_back(current_packet - i);
      }
      current_packet = current_packet - first_ack_range;

      for (uint64_t i = 0; i < ack_range_count; ++i) {
        uint64_t gap = 0;
        uint64_t length = 0;
        if (!ReadVarInt(buf, len, offset, gap)) return false;
        if (!ReadVarInt(buf, len, offset, length)) return false;

        if (current_packet < gap + 2) return false;
        current_packet = current_packet - gap - 2;

        if (current_packet < length) return false;
        for (uint64_t j = 0; j <= length; ++j) {
          f.acknowledged_packets.push_back(current_packet - j);
        }
        current_packet = current_packet - length;
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
      if (cid_len < 1 || cid_len > 20) return false;
      if (!ConnectionId::Deserialize(buf, len, offset, f.connection_id,
                                     cid_len))
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
    case FrameType::CONNECTION_CLOSE:
    case FrameType::CONNECTION_CLOSE_APP: {
      ConnectionCloseFrame f;
      if (!ReadVarInt(buf, len, offset, f.error_code)) return false;
      if (frame_type_raw == 0x1c) {
        uint64_t frame_type_close = 0;
        if (!ReadVarInt(buf, len, offset, frame_type_close)) return false;
      }
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
class QuicConnection;

namespace internal {
int quic_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
                         const SSL_CIPHER *cipher, const uint8_t *secret,
                         size_t secret_len);
int quic_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
                          const SSL_CIPHER *cipher, const uint8_t *secret,
                          size_t secret_len);
int quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                            const uint8_t *data, size_t len);
int quic_flush_flight(SSL *ssl);
int quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert);

extern const SSL_QUIC_METHOD quic_method;

std::vector<uint8_t> SerializeAlpnProtos(
    const std::vector<std::string> &protos);

int QuicAlpnSelectCallback(SSL *ssl, const unsigned char **out,
                           unsigned char *outlen, const unsigned char *in,
                           unsigned int inlen, void *arg);

void SetQuicTransportParams(SSL *ssl);

// Returns the shared singleton SSL_CTX for outgoing QUIC client connections.
// Server-side connections always supply their own ssl_ctx_ via QuicServer,
// so no server branch is needed here.
inline SSL_CTX *GetClientSSLContext() {
  static std::mutex mtx;
  std::lock_guard<std::mutex> lock(mtx);
  static SSL_CTX *client_ctx = nullptr;
  static bool initialized = false;
  if (!initialized) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    initialized = true;
  }
  if (!client_ctx) {
    client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION);
    SSL_CTX_set_keylog_callback(client_ctx, QuicKeylogCallback);
    SSL_CTX_set_quic_method(client_ctx, &quic_method);
  }
  return client_ctx;
}

inline void DeriveInitialKeys(const ConnectionId &dest_conn_id, bool is_server,
                              std::vector<uint8_t> &read_key,
                              std::vector<uint8_t> &read_iv,
                              std::vector<uint8_t> &read_hp,
                              std::vector<uint8_t> &write_key,
                              std::vector<uint8_t> &write_iv,
                              std::vector<uint8_t> &write_hp) {
  // RFC 9001 §5.2 — QUIC v1 initial salt
  const std::vector<uint8_t> salt = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                     0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                     0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
  std::vector<uint8_t> dest_conn_id_bytes(
      dest_conn_id.data, dest_conn_id.data + dest_conn_id.length);
  std::vector<uint8_t> initial_secret = HKDF_Extract(salt, dest_conn_id_bytes);

  std::vector<uint8_t> client_secret =
      HKDF_Expand_Label(initial_secret, "client in", {}, 32);
  std::vector<uint8_t> server_secret =
      HKDF_Expand_Label(initial_secret, "server in", {}, 32);

  if (is_server) {
    read_key = HKDF_Expand_Label(client_secret, "quic key", {}, 16);
    read_iv = HKDF_Expand_Label(client_secret, "quic iv", {}, 12);
    read_hp = HKDF_Expand_Label(client_secret, "quic hp", {}, 16);
    write_key = HKDF_Expand_Label(server_secret, "quic key", {}, 16);
    write_iv = HKDF_Expand_Label(server_secret, "quic iv", {}, 12);
    write_hp = HKDF_Expand_Label(server_secret, "quic hp", {}, 16);
  } else {
    read_key = HKDF_Expand_Label(server_secret, "quic key", {}, 16);
    read_iv = HKDF_Expand_Label(server_secret, "quic iv", {}, 12);
    read_hp = HKDF_Expand_Label(server_secret, "quic hp", {}, 16);
    write_key = HKDF_Expand_Label(client_secret, "quic key", {}, 16);
    write_iv = HKDF_Expand_Label(client_secret, "quic iv", {}, 12);
    write_hp = HKDF_Expand_Label(client_secret, "quic hp", {}, 16);
  }

  Log(LogSeverity::Info, "DeriveKeys",
      std::string(is_server ? "Server" : "Client") +
          " derived initial keys successfully.");
}

inline void DeriveZeroRTTKeys(const ConnectionId &dest_conn_id, bool is_server,
                              std::vector<uint8_t> &read_key,
                              std::vector<uint8_t> &read_iv,
                              std::vector<uint8_t> &write_key,
                              std::vector<uint8_t> &write_iv) {
  const std::vector<uint8_t> salt = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                     0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                                     0xee, 0xff, 0x00, 0x11, 0x22, 0x33};
  std::vector<uint8_t> dest_conn_id_bytes(
      dest_conn_id.data, dest_conn_id.data + dest_conn_id.length);
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
  std::vector<uint8_t> cid_bytes(cid.data, cid.data + cid.length);
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
      const std::vector<uint8_t> *iv = nullptr,
      const std::vector<uint8_t> *hp = nullptr) const {
    std::vector<uint8_t> buf;
    buf.reserve(256);

    std::vector<uint8_t> payload;
    payload.reserve(256);
    for (const auto &frame : frames) {
      internal::SerializeFrame(payload, frame);
    }

    bool is_long = (packet_type == 1 || packet_type == 2 || packet_type == 3);
    size_t pn_offset = 0;

    if (is_long) {
      // Long Header (Initial, Handshake, or 0-RTT)
      uint8_t first = 0;
      if (packet_type == 1)
        first = 0xc3;
      else if (packet_type == 2)
        first = 0xe3;
      else if (packet_type == 3)
        first = 0xd3;

      internal::WriteUint8(buf, first);
      internal::WriteUint32(buf, 0x00000001);           // Version (QUIC v1)
      internal::WriteUint8(buf, connection_id.length);  // Dest ID Len
      connection_id.Serialize(buf);
      internal::WriteUint8(buf, source_connection_id.length);  // Src ID Len
      source_connection_id.Serialize(buf);

      if (packet_type == 1) {
        internal::WriteVarInt(buf, 0);  // Token Len
      }

      // Length = Packet Number size (4 bytes) + payload size + 16 (tag size)
      uint64_t packet_len = 4 + payload.size() + (key ? 16 : 0);
      internal::WriteVarInt(buf, packet_len);

      pn_offset = buf.size();
      internal::WriteUint32(buf, static_cast<uint32_t>(packet_number));
    } else {
      // Short Header (1-RTT)
      internal::WriteUint8(buf, 0x43);
      connection_id.Serialize(buf);
      pn_offset = buf.size();
      internal::WriteUint32(buf, static_cast<uint32_t>(packet_number));
    }

    std::vector<uint8_t> final_payload;
    if (key && iv && !key->empty() && !iv->empty()) {
      std::vector<uint8_t> pkt_iv = *iv;
      for (size_t i = 0; i < 8 && i < pkt_iv.size(); ++i) {
        pkt_iv[pkt_iv.size() - 1 - i] ^= (packet_number >> (i * 8)) & 0xFF;
      }
      std::vector<uint8_t> ciphertext;
      if (internal::EncryptData(*key, pkt_iv, payload, ciphertext, buf)) {
        final_payload = std::move(ciphertext);
      } else {
        internal::Log(
            LogSeverity::Error, "QuicPacket",
            "Encryption failed for packet type " + std::to_string(packet_type));
        final_payload = std::move(payload);  // fallback
      }
    } else {
      final_payload = std::move(payload);
    }

    buf.insert(buf.end(), final_payload.begin(), final_payload.end());

    // Apply Header Protection (HP) masking
    if (hp && !hp->empty()) {
      size_t sample_offset = pn_offset + 4;
      if (buf.size() >= sample_offset + 16) {
        uint8_t mask[16];
        if (internal::ComputeHPMask(*hp, buf.data() + sample_offset, mask)) {
          buf[0] ^= (mask[0] & (is_long ? 0x0f : 0x1f));
          for (size_t i = 0; i < 4; ++i) {
            buf[pn_offset + i] ^= mask[1 + i];
          }
        }
      }
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
      if (dest_len > 20) return false;
      if (data.size() < 6 + dest_len) return false;
      offset = 6;
      return ConnectionId::Deserialize(data.data(), data.size(), offset, out,
                                       dest_len);
    } else {
      // Short Header
      if (data.size() < 9) return false;
      offset = 1;
      return ConnectionId::Deserialize(data.data(), data.size(), offset, out,
                                       8);
    }
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
                          const std::vector<uint8_t> *iv = nullptr,
                          const std::vector<uint8_t> *hp = nullptr,
                          uint8_t expected_conn_id_len = 8) {
    if (data.empty()) return false;
    const uint8_t *buf = data.data();
    size_t len = data.size();

    // Work on a copy to unmask Header Protection (HP)
    std::vector<uint8_t> dec_data = data;
    uint8_t *dec_buf = dec_data.data();

    uint8_t raw_first = dec_buf[0];
    bool is_long = (raw_first & 0x80) != 0;

    size_t pn_offset = 0;
    if (is_long) {
      size_t offset = 5;
      if (offset + 1 > len) return false;
      uint8_t dest_len = dec_buf[offset++];
      if (offset + dest_len > len) return false;
      offset += dest_len;
      if (offset + 1 > len) return false;
      uint8_t src_len = dec_buf[offset++];
      if (offset + src_len > len) return false;
      offset += src_len;

      uint8_t type = (raw_first >> 4) & 0x03;
      if (type == 0) {  // Initial
        uint64_t token_len = 0;
        if (!internal::ReadVarInt(dec_buf, len, offset, token_len))
          return false;
        if (offset + token_len > len) return false;
        offset += token_len;
      }

      uint64_t packet_len = 0;
      if (!internal::ReadVarInt(dec_buf, len, offset, packet_len)) return false;
      pn_offset = offset;
    } else {
      pn_offset = 1 + expected_conn_id_len;
    }

    size_t sample_offset = pn_offset + 4;
    if (hp && !hp->empty() && len >= sample_offset + 16) {
      uint8_t mask[16];
      if (internal::ComputeHPMask(*hp, dec_buf + sample_offset, mask)) {
        // Print detailed HP debug info

        uint8_t decrypted_first =
            raw_first ^ (mask[0] & (is_long ? 0x0f : 0x1f));
        dec_buf[0] = decrypted_first;
        uint8_t pn_len = (decrypted_first & 0x03) + 1;
        for (size_t i = 0; i < pn_len && pn_offset + i < len; ++i) {
          dec_buf[pn_offset + i] ^= mask[1 + i];
        }
      }
    }

    size_t offset = 0;
    uint8_t first = dec_buf[offset++];

    if (is_long) {
      uint8_t type = (first >> 4) & 0x03;
      if (type == 0) {
        out.packet_type = 1;  // Initial
      } else if (type == 2) {
        out.packet_type = 2;  // Handshake
      } else if (type == 1) {
        out.packet_type = 3;  // 0-RTT
      } else {
        return false;
      }

      uint32_t version = 0;
      if (!internal::ReadUint32(dec_buf, len, offset, version)) return false;
      if (version != 0x00000001) return false;

      uint8_t dest_len = 0;
      if (!internal::ReadUint8(dec_buf, len, offset, dest_len)) return false;
      if (dest_len > 20) return false;
      if (!ConnectionId::Deserialize(dec_buf, len, offset, out.connection_id,
                                     dest_len))
        return false;

      uint8_t src_len = 0;
      if (!internal::ReadUint8(dec_buf, len, offset, src_len)) return false;
      if (src_len > 20) return false;
      if (!ConnectionId::Deserialize(dec_buf, len, offset,
                                     out.source_connection_id, src_len))
        return false;

      if (out.packet_type == 1) {
        uint64_t token_len = 0;
        if (!internal::ReadVarInt(dec_buf, len, offset, token_len))
          return false;
        if (token_len > 0) {
          if (offset + token_len > len) return false;
          offset += token_len;
        }
      }

      uint64_t packet_len = 0;
      if (!internal::ReadVarInt(dec_buf, len, offset, packet_len)) return false;
      if (offset + packet_len > len) return false;

      uint8_t pn_len = (first & 0x03) + 1;
      uint32_t pkt_num = 0;
      for (size_t i = 0; i < pn_len; ++i) {
        pkt_num = (pkt_num << 8) | dec_buf[offset++];
      }
      out.packet_number = pkt_num;

      size_t payload_len = packet_len - pn_len;
      if (offset + payload_len > len) return false;

      std::vector<uint8_t> payload_buf(dec_buf + offset,
                                       dec_buf + offset + payload_len);
      size_t AAD_offset = offset;
      offset += payload_len;

      std::vector<uint8_t> plaintext;
      if (key && iv && !key->empty() && !iv->empty()) {
        std::vector<uint8_t> pkt_iv = *iv;
        for (size_t i = 0; i < 8 && i < pkt_iv.size(); ++i) {
          pkt_iv[pkt_iv.size() - 1 - i] ^=
              (out.packet_number >> (i * 8)) & 0xFF;
        }
        std::vector<uint8_t> aad(dec_buf, dec_buf + AAD_offset);
        if (!internal::DecryptData(*key, pkt_iv, payload_buf, plaintext, aad)) {
          internal::Log(LogSeverity::Warn, "QuicPacket",
                        "Decryption failed for packet type " +
                            std::to_string(out.packet_type));
          return false;
        }
      } else {
        plaintext = std::move(payload_buf);
      }

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
      if (!ConnectionId::Deserialize(dec_buf, len, offset, out.connection_id,
                                     expected_conn_id_len))
        return false;

      uint8_t pn_len = (first & 0x03) + 1;
      uint32_t pkt_num = 0;
      for (size_t i = 0; i < pn_len; ++i) {
        pkt_num = (pkt_num << 8) | dec_buf[offset++];
      }
      out.packet_number = pkt_num;

      std::vector<uint8_t> payload_buf(dec_buf + offset, dec_buf + len);
      size_t AAD_offset = offset;
      offset = len;

      std::vector<uint8_t> plaintext;
      if (key && iv && !key->empty() && !iv->empty()) {
        std::vector<uint8_t> pkt_iv = *iv;
        for (size_t i = 0; i < 8 && i < pkt_iv.size(); ++i) {
          pkt_iv[pkt_iv.size() - 1 - i] ^=
              (out.packet_number >> (i * 8)) & 0xFF;
        }
        std::vector<uint8_t> aad(dec_buf, dec_buf + AAD_offset);
        if (!internal::DecryptData(*key, pkt_iv, payload_buf, plaintext, aad)) {
          internal::Log(LogSeverity::Warn, "QuicPacket",
                        "Decryption failed for short header packet");
          return false;
        }
      } else {
        plaintext = std::move(payload_buf);
      }

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

    if (frame.offset + frame.data.size() <= recv_offset_) {
      // Already received and processed
      return true;
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

  bool IsSendBufferEmpty() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return send_buffer_.empty();
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

    const size_t MAX_CWND = 30 * max_datagram_size_;
    if (cwnd_ > MAX_CWND) {
      cwnd_ = MAX_CWND;
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
  std::vector<uint8_t> initial_read_hp;
  std::vector<uint8_t> initial_write_key;
  std::vector<uint8_t> initial_write_iv;
  std::vector<uint8_t> initial_write_hp;

  // Handshake keys
  std::vector<uint8_t> handshake_read_key;
  std::vector<uint8_t> handshake_read_iv;
  std::vector<uint8_t> handshake_read_hp;
  std::vector<uint8_t> handshake_write_key;
  std::vector<uint8_t> handshake_write_iv;
  std::vector<uint8_t> handshake_write_hp;

  // 1-RTT keys
  std::vector<uint8_t> read_key;
  std::vector<uint8_t> read_iv;
  std::vector<uint8_t> read_hp;
  std::vector<uint8_t> write_key;
  std::vector<uint8_t> write_iv;
  std::vector<uint8_t> write_hp;

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
                 const ConnectionId &original_dest_id = ConnectionId{},
                 const std::vector<std::string> &alpn_protos = {"h3"})
      : local_connection_id_(local_id),
        remote_connection_id_(remote_id),
        peer_(peer),
        is_server_(is_server),
        original_destination_connection_id_(original_dest_id) {
    crypto_ctx_ = std::make_shared<QuicCryptoContext>();
    SSL_CTX *ctx = custom_ctx ? custom_ctx : internal::GetClientSSLContext();
    crypto_ctx_->ssl = SSL_new(ctx);
    SSL_set_app_data(crypto_ctx_->ssl, this);
    internal::SetQuicTransportParams(crypto_ctx_->ssl);
    if (!is_server) {
      std::vector<uint8_t> alpn_wire =
          internal::SerializeAlpnProtos(alpn_protos);
      SSL_set_alpn_protos(crypto_ctx_->ssl, alpn_wire.data(), alpn_wire.size());
    }
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
        crypto_ctx_->initial_read_iv, crypto_ctx_->initial_read_hp,
        crypto_ctx_->initial_write_key, crypto_ctx_->initial_write_iv,
        crypto_ctx_->initial_write_hp);
    internal::DeriveZeroRTTKeys(
        initial_id, is_server, crypto_ctx_->zerortt_read_key,
        crypto_ctx_->zerortt_read_iv, crypto_ctx_->zerortt_write_key,
        crypto_ctx_->zerortt_write_iv);
    congestion_controller_ =
        CreateCongestionController(CongestionControlAlgorithm::NewReno);
  }

  void HandleKeylogLine(const std::string &line) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : line) {
      if (c == ' ') {
        if (!current.empty()) {
          parts.push_back(current);
          current.clear();
        }
      } else if (c != '\n' && c != '\r') {
        current += c;
      }
    }
    if (!current.empty()) {
      parts.push_back(current);
    }
    if (parts.size() < 3) return;

    std::string type = parts[0];
    std::string secret_hex = parts[2];

    if (type == "CLIENT_HANDSHAKE_TRAFFIC_SECRET") {
      std::vector<uint8_t> secret = internal::HexToBytes(secret_hex);
      size_t key_len = (secret.size() == 48) ? 32 : 16;
      size_t hp_len = (secret.size() == 48) ? 32 : 16;
      if (is_server_) {
        crypto_ctx_->handshake_read_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->handshake_read_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->handshake_read_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      } else {
        crypto_ctx_->handshake_write_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->handshake_write_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->handshake_write_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      }
    } else if (type == "SERVER_HANDSHAKE_TRAFFIC_SECRET") {
      std::vector<uint8_t> secret = internal::HexToBytes(secret_hex);
      size_t key_len = (secret.size() == 48) ? 32 : 16;
      size_t hp_len = (secret.size() == 48) ? 32 : 16;
      if (is_server_) {
        crypto_ctx_->handshake_write_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->handshake_write_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->handshake_write_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      } else {
        crypto_ctx_->handshake_read_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->handshake_read_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->handshake_read_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      }
    } else if (type == "CLIENT_TRAFFIC_SECRET_0") {
      std::vector<uint8_t> secret = internal::HexToBytes(secret_hex);
      size_t key_len = (secret.size() == 48) ? 32 : 16;
      size_t hp_len = (secret.size() == 48) ? 32 : 16;
      if (is_server_) {
        crypto_ctx_->read_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->read_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->read_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      } else {
        crypto_ctx_->write_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->write_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->write_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      }
    } else if (type == "SERVER_TRAFFIC_SECRET_0") {
      std::vector<uint8_t> secret = internal::HexToBytes(secret_hex);
      size_t key_len = (secret.size() == 48) ? 32 : 16;
      size_t hp_len = (secret.size() == 48) ? 32 : 16;
      if (is_server_) {
        crypto_ctx_->write_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->write_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->write_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      } else {
        crypto_ctx_->read_key =
            internal::HKDF_Expand_Label_QUIC(secret, "key", {}, key_len);
        crypto_ctx_->read_iv =
            internal::HKDF_Expand_Label_QUIC(secret, "iv", {}, 12);
        crypto_ctx_->read_hp =
            internal::HKDF_Expand_Label_QUIC(secret, "hp", {}, hp_len);
      }
    }
  }
  void AppendPendingHandshakeData(int level, const uint8_t *data, size_t len) {
    auto &buf = pending_handshake_data_[level];
    buf.insert(buf.end(), data, data + len);
  }

  ConnectionId GetLocalConnectionId() const { return local_connection_id_; }
  bool IsServer() const { return is_server_; }
  const ConnectionId &GetOriginalDestinationConnectionId() const {
    return original_destination_connection_id_;
  }
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
  QuicPacket CreatePacketLocked(std::vector<QuicFrame> frames,
                                uint8_t packet_type = 0) {
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

  QuicPacket CreatePacket(std::vector<QuicFrame> frames,
                          uint8_t packet_type = 0) {
    std::lock_guard<std::mutex> lock(mtx_);
    return CreatePacketLocked(std::move(frames), packet_type);
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
    const std::vector<uint8_t> *write_hp = nullptr;
    if (crypto_ctx_) {
      if (pkt.packet_type == 1) {
        write_key = &crypto_ctx_->initial_write_key;
        write_iv = &crypto_ctx_->initial_write_iv;
        write_hp = &crypto_ctx_->initial_write_hp;
      } else if (pkt.packet_type == 2) {
        write_key = crypto_ctx_->handshake_write_key.empty()
                        ? &crypto_ctx_->initial_write_key
                        : &crypto_ctx_->handshake_write_key;
        write_iv = crypto_ctx_->handshake_write_iv.empty()
                       ? &crypto_ctx_->initial_write_iv
                       : &crypto_ctx_->handshake_write_iv;
        write_hp = crypto_ctx_->handshake_write_hp.empty()
                       ? &crypto_ctx_->initial_write_hp
                       : &crypto_ctx_->handshake_write_hp;
      } else if (pkt.packet_type == 3) {
        write_key = &crypto_ctx_->zerortt_write_key;
        write_iv = &crypto_ctx_->zerortt_write_iv;
        write_hp = &crypto_ctx_->initial_write_hp;
      } else {
        if (crypto_ctx_->handshake_complete) {
          write_key = &crypto_ctx_->write_key;
          write_iv = &crypto_ctx_->write_iv;
          write_hp = &crypto_ctx_->write_hp;
        } else {
          write_key = &crypto_ctx_->initial_write_key;
          write_iv = &crypto_ctx_->initial_write_iv;
          write_hp = &crypto_ctx_->initial_write_hp;
        }
      }
    }
    auto bytes = pkt.Serialize(write_key, write_iv, write_hp);

    auto it = sent_packets_.find(pkt.packet_number);
    if (it != sent_packets_.end()) {
      it->second.packet_size = bytes.size();
      if (congestion_controller_) {
        congestion_controller_->OnPacketSent(pkt.packet_number, bytes.size());
      }
    }
    return bytes;
  }

  bool DeserializePacket(const std::vector<uint8_t> &data, QuicPacket &out,
                         bool &was_buffered) {
    std::lock_guard<std::mutex> lock(mtx_);
    was_buffered = false;
    const std::vector<uint8_t> *read_key = nullptr;
    const std::vector<uint8_t> *read_iv = nullptr;
    const std::vector<uint8_t> *read_hp = nullptr;
    uint8_t packet_type = 0;
    if (crypto_ctx_) {
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
      if (packet_type == 1) {
        read_key = &crypto_ctx_->initial_read_key;
        read_iv = &crypto_ctx_->initial_read_iv;
        read_hp = &crypto_ctx_->initial_read_hp;
      } else if (packet_type == 2) {
        bool hs_empty = crypto_ctx_->handshake_read_key.empty();
        read_key = hs_empty ? &crypto_ctx_->initial_read_key
                            : &crypto_ctx_->handshake_read_key;
        read_iv = hs_empty ? &crypto_ctx_->initial_read_iv
                           : &crypto_ctx_->handshake_read_iv;
        read_hp = hs_empty ? &crypto_ctx_->initial_read_hp
                           : &crypto_ctx_->handshake_read_hp;
      } else if (packet_type == 3) {
        read_key = &crypto_ctx_->zerortt_read_key;
        read_iv = &crypto_ctx_->zerortt_read_iv;
        read_hp = &crypto_ctx_->initial_read_hp;
      } else {
        if (crypto_ctx_->handshake_complete) {
          read_key = &crypto_ctx_->read_key;
          read_iv = &crypto_ctx_->read_iv;
          read_hp = &crypto_ctx_->read_hp;
        } else {
          // 1-RTT packet arrived before handshake is complete — buffer it
          // for replay once 1-RTT keys are available (RFC 9001 §5.7).
          pending_1rtt_packets_.push_back(data);
          was_buffered = true;
          return false;
        }
      }
    }
    uint8_t expected_len = local_connection_id_.length;
    return QuicPacket::Deserialize(data, out, read_key, read_iv, read_hp,
                                   expected_len);
  }

  bool DeserializePacket(const std::vector<uint8_t> &data, QuicPacket &out) {
    bool was_buffered = false;
    return DeserializePacket(data, out, was_buffered);
  }

  // Drains any 1-RTT packets buffered before handshake completed as raw UDP
  // datagrams.
  std::vector<std::vector<uint8_t>> DrainPending1RawPackets() {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::vector<uint8_t>> result;
    std::swap(result, pending_1rtt_packets_);
    return result;
  }

  // Called for each received CryptoFrame. Performs in-order stream reassembly
  // per encryption level before feeding data to the TLS layer (RFC 9000 §7.4).
  std::vector<QuicPacket> ProcessCrypto(uint64_t frame_offset,
                                        const std::vector<uint8_t> &in_data,
                                        int ssl_level = 0) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<QuicPacket> pkts;
    if (!crypto_ctx_ || crypto_ctx_->handshake_complete) return pkts;

    // --- CRYPTO stream reassembly (RFC 9000 §7.4) ---
    if (!in_data.empty()) {
      // Store the incoming fragment under the expected ssl_level key
      auto &ooo = crypto_rx_ooo_[ssl_level];
      ooo[frame_offset] = in_data;

      // Deliver as many contiguous bytes as possible to the TLS layer.
      // Always use SSL_quic_read_level() for SSL_provide_quic_data — it
      // reflects the level LibreSSL currently expects, which may differ from
      // the packet's ssl_level once the handshake progresses.
      auto &next = crypto_rx_next_offset_[ssl_level];
      while (true) {
        auto it = ooo.find(next);
        if (it == ooo.end()) break;  // Gap – wait for missing fragment

        const auto &frag = it->second;
        enum ssl_encryption_level_t current_level =
            SSL_quic_read_level(crypto_ctx_->ssl);
        int prov_ret = SSL_provide_quic_data(crypto_ctx_->ssl, current_level,
                                             frag.data(), frag.size());
        if (prov_ret <= 0) {
          char err_buf[256];
          ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
          internal::Log(
              LogSeverity::Error, "ProcessCrypto",
              std::string("SSL_provide_quic_data failed: ") + err_buf);
          break;  // Stop feeding if rejected
        }
        next += frag.size();
        ooo.erase(it);
      }
    }

    pending_handshake_data_.clear();

    int ret = SSL_do_handshake(crypto_ctx_->ssl);
    if (ret <= 0) {
      int err = SSL_get_error(crypto_ctx_->ssl, ret);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        char err_buf[256];
        const char *file = nullptr;
        int line = 0;
        unsigned long e;
        while ((e = ERR_get_error_line(&file, &line)) != 0) {
          ERR_error_string_n(e, err_buf, sizeof(err_buf));
          internal::Log(LogSeverity::Error, "ProcessCrypto",
                        std::string("TLS handshake error: ") + err_buf);
        }
      }
    }

    // Level 0 (Initial) -> Initial packet (type 1)
    if (pending_handshake_data_.count(0) &&
        !pending_handshake_data_[0].empty()) {
      const auto &data = pending_handshake_data_[0];
      size_t offset = 0;
      while (offset < data.size()) {
        size_t chunk_size =
            std::min(data.size() - offset, static_cast<size_t>(900));
        CryptoFrame cf;
        cf.offset = offset;
        cf.data = std::vector<uint8_t>(data.begin() + offset,
                                       data.begin() + offset + chunk_size);
        std::vector<QuicFrame> frames;
        if (offset == 0) {
          auto ack = GenerateAckLocked(1);
          if (!ack.acknowledged_packets.empty()) {
            frames.push_back(std::move(ack));
          }
        }
        frames.push_back(std::move(cf));
        pkts.push_back(CreatePacketLocked(std::move(frames), 1));
        offset += chunk_size;
      }
    }
    // Level 2 (Handshake) -> Handshake packet (type 2)
    if (pending_handshake_data_.count(2) &&
        !pending_handshake_data_[2].empty()) {
      const auto &data = pending_handshake_data_[2];
      size_t offset = 0;
      while (offset < data.size()) {
        size_t chunk_size =
            std::min(data.size() - offset, static_cast<size_t>(900));
        CryptoFrame cf;
        cf.offset = offset;
        cf.data = std::vector<uint8_t>(data.begin() + offset,
                                       data.begin() + offset + chunk_size);
        std::vector<QuicFrame> frames;
        if (offset == 0) {
          auto ack = GenerateAckLocked(2);
          if (!ack.acknowledged_packets.empty()) {
            frames.push_back(std::move(ack));
          }
        }
        frames.push_back(std::move(cf));
        pkts.push_back(CreatePacketLocked(std::move(frames), 2));
        offset += chunk_size;
      }
    }

    if (ret == 1) {
      crypto_ctx_->handshake_complete = true;
    }
    return pkts;
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
      uint64_t target_pn = pkt_num;
      auto map_it = retransmitted_packets_.find(target_pn);
      while (map_it != retransmitted_packets_.end()) {
        target_pn = map_it->second;
        map_it = retransmitted_packets_.find(target_pn);
      }

      auto it = sent_packets_.find(target_pn);
      if (it != sent_packets_.end()) {
        // Update RTT estimate (RFC 9002 §5)
        double sample_ms = std::chrono::duration<double, std::milli>(
                               now - it->second.send_time)
                               .count();
        if (sample_ms > 0.0) {
          double rtt_diff = std::abs(sample_ms - smoothed_rtt_ms_);
          smoothed_rtt_ms_ = 0.875 * smoothed_rtt_ms_ + 0.125 * sample_ms;
          rtt_var_ms_ = 0.75 * rtt_var_ms_ + 0.25 * rtt_diff;
        }

        if (congestion_controller_) {
          congestion_controller_->OnPacketAcked(
              target_pn, it->second.packet_size, it->second.send_time, now);
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
  void RecordReceivedPacket(uint64_t packet_number, uint8_t packet_type) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (packet_type > 3) return;
    received_packets_[packet_type].push_back(packet_number);
    if (packet_number > largest_received_packet_[packet_type]) {
      largest_received_packet_[packet_type] = packet_number;
    }
  }

  /**
   * @brief Generates an ACK frame for received packets (locked context).
   */
  AckFrame GenerateAckLocked(uint8_t packet_type) {
    AckFrame ack;
    if (packet_type > 3) return ack;
    ack.largest_acknowledged = largest_received_packet_[packet_type];
    ack.ack_delay_us = 0;
    ack.acknowledged_packets = received_packets_[packet_type];
    received_packets_[packet_type].clear();
    return ack;
  }

  /**
   * @brief Generates an ACK frame for received packets.
   * @return An AckFrame acknowledging all unacknowledged received packets.
   */
  AckFrame GenerateAck(uint8_t packet_type) {
    std::lock_guard<std::mutex> lock(mtx_);
    return GenerateAckLocked(packet_type);
  }

  /**
   * @brief Returns packets that are overdue for retransmission.
   * @param timeout Time since send after which a packet is considered lost.
   */
  std::vector<QuicPacket> GetRetransmissions(
      std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) {
    std::lock_guard<std::mutex> lock(mtx_);
    // RFC 9002 §6.2.1: RTO = SRTT + max(4*RTTVAR, 1ms), floor at 200ms
    // The 200ms floor prevents sub-millisecond RTO on loopback which causes
    // exponential retransmission storms.
    double computed_rto_ms =
        smoothed_rtt_ms_ + std::max(4.0 * rtt_var_ms_, 1.0);
    computed_rto_ms = std::max(computed_rto_ms, 200.0);
    auto effective_timeout =
        (timeout.count() > 0)
            ? timeout
            : std::chrono::milliseconds(static_cast<int64_t>(computed_rto_ms));
    auto now = std::chrono::steady_clock::now();
    std::vector<QuicPacket> retransmits;

    std::vector<uint64_t> lost_packets;
    std::vector<LostPacketInfo> lost_infos;
    for (auto &[pkt_num, info] : sent_packets_) {
      if (now - info.send_time > effective_timeout) {
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
        QuicPacket pkt;
        pkt.connection_id = remote_connection_id_;
        pkt.source_connection_id = local_connection_id_;
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

        // Update any existing mappings to point to the new packet number
        for (auto &[old_pn, new_pn] : retransmitted_packets_) {
          if (new_pn == pkt_num) {
            new_pn = pkt.packet_number;
          }
        }
        retransmitted_packets_[pkt_num] = pkt.packet_number;

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
    if (state_ == ConnectionState::Closed) {
      stats.streams_closed = total_streams_opened_;
    } else {
      uint64_t closed = 0;
      for (const auto &[id, stream] : streams_) {
        if (stream->GetState() == StreamState::Closed) {
          closed++;
        }
      }
      stats.streams_closed = closed;
    }
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
          static int conn_blocked_count = 0;
          if (conn_blocked_count++ % 5000 == 0) {
            internal::Log(LogSeverity::Info, "FlowControl",
                          std::string(is_server_ ? "Server" : "Client") +
                              ": Blocked on connection limit: max_send_data_=" +
                              std::to_string(max_send_data_) +
                              ", total_stream_bytes_sent_=" +
                              std::to_string(total_stream_bytes_sent_));
          }
          break;
        }

        auto frames = stream->PullWriteFrames(conn_allowed);
        if (frames.empty()) {
          static int stream_blocked_count = 0;
          if (stream_blocked_count++ % 5000 == 0 &&
              stream->GetState() == StreamState::Open &&
              !stream->IsSendBufferEmpty()) {
            internal::Log(
                LogSeverity::Info, "FlowControl",
                std::string(is_server_ ? "Server" : "Client") +
                    ": Blocked on stream/conn limit: max_send_offset_=" +
                    std::to_string(stream->GetMaxSendOffset()) +
                    ", send_offset_=" +
                    std::to_string(stream->GetSendOffset()));
          }
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
  ConnectionId original_destination_connection_id_;
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
  std::unordered_map<uint64_t, uint64_t> retransmitted_packets_;

  // RTT estimation (RFC 9002 §5)
  double smoothed_rtt_ms_ = 100.0;  // initial conservative estimate
  double rtt_var_ms_ = 50.0;

  // Received packet tracking for ACK generation per packet number space
  std::vector<uint64_t> received_packets_[4];
  uint64_t largest_received_packet_[4] = {0, 0, 0, 0};

  // Short-header (1-RTT) packets that arrived before handshake_complete.
  // Replayed immediately after 1-RTT keys are available.
  std::vector<std::vector<uint8_t>> pending_1rtt_packets_;

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
  std::map<int, std::vector<uint8_t>> pending_handshake_data_;

  // CRYPTO stream reassembly per encryption level (RFC 9000 §7.4)
  // Maps level -> next byte offset we expect to deliver to TLS
  std::map<int, uint64_t> crypto_rx_next_offset_;
  // Out-of-order fragments: level -> map<offset, data>
  std::map<int, std::map<uint64_t, std::vector<uint8_t>>> crypto_rx_ooo_;
};

namespace internal {

inline void DeriveQuicKeys(const uint8_t *secret, size_t secret_len,
                           std::vector<uint8_t> &key, std::vector<uint8_t> &iv,
                           std::vector<uint8_t> &hp) {
  std::vector<uint8_t> secret_vec(secret, secret + secret_len);
  size_t key_len = (secret_len == 48) ? 32 : 16;
  size_t hp_len = (secret_len == 48) ? 32 : 16;
  key = HKDF_Expand_Label_QUIC(secret_vec, "key", {}, key_len);
  iv = HKDF_Expand_Label_QUIC(secret_vec, "iv", {}, 12);
  hp = HKDF_Expand_Label_QUIC(secret_vec, "hp", {}, hp_len);
}

inline int quic_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
                                const SSL_CIPHER *cipher, const uint8_t *secret,
                                size_t secret_len) {
  auto *conn = static_cast<::cppquic::QuicConnection *>(SSL_get_app_data(ssl));
  if (!conn) return 0;

  auto crypto_ctx = conn->GetCryptoContext();
  if (!crypto_ctx) return 0;

  std::vector<uint8_t> key, iv, hp;
  DeriveQuicKeys(secret, secret_len, key, iv, hp);

  if (level == ssl_encryption_handshake) {
    crypto_ctx->handshake_read_key = key;
    crypto_ctx->handshake_read_iv = iv;
    crypto_ctx->handshake_read_hp = hp;
  } else if (level == ssl_encryption_application) {
    crypto_ctx->read_key = key;
    crypto_ctx->read_iv = iv;
    crypto_ctx->read_hp = hp;
  }
  return 1;
}

inline int quic_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
                                 const SSL_CIPHER *cipher,
                                 const uint8_t *secret, size_t secret_len) {
  auto *conn = static_cast<::cppquic::QuicConnection *>(SSL_get_app_data(ssl));
  if (!conn) return 0;

  auto crypto_ctx = conn->GetCryptoContext();
  if (!crypto_ctx) return 0;

  std::vector<uint8_t> key, iv, hp;
  DeriveQuicKeys(secret, secret_len, key, iv, hp);

  if (level == ssl_encryption_handshake) {
    crypto_ctx->handshake_write_key = key;
    crypto_ctx->handshake_write_iv = iv;
    crypto_ctx->handshake_write_hp = hp;
  } else if (level == ssl_encryption_application) {
    crypto_ctx->write_key = key;
    crypto_ctx->write_iv = iv;
    crypto_ctx->write_hp = hp;
  }
  return 1;
}

inline int quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                                   const uint8_t *data, size_t len) {
  auto *conn = static_cast<::cppquic::QuicConnection *>(SSL_get_app_data(ssl));
  if (!conn) return 0;
  conn->AppendPendingHandshakeData(static_cast<int>(level), data, len);
  return 1;
}

inline int quic_flush_flight(SSL *ssl) { return 1; }

inline int quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level,
                           uint8_t alert) {
  return 1;
}

inline const SSL_QUIC_METHOD quic_method = {
    nullptr,                  // set_encryption_secrets
    quic_add_handshake_data,  // add_handshake_data
    quic_flush_flight,        // flush_flight
    quic_send_alert,          // send_alert
    quic_set_read_secret,     // set_read_secret
    quic_set_write_secret     // set_write_secret
};

inline std::vector<uint8_t> SerializeAlpnProtos(
    const std::vector<std::string> &protos) {
  std::vector<uint8_t> wire;
  for (const auto &p : protos) {
    if (p.empty() || p.size() > 255) continue;
    wire.push_back(static_cast<uint8_t>(p.size()));
    wire.insert(wire.end(), p.begin(), p.end());
  }
  return wire;
}

inline int QuicAlpnSelectCallback(SSL *ssl, const unsigned char **out,
                                  unsigned char *outlen,
                                  const unsigned char *in, unsigned int inlen,
                                  void *arg) {
  for (unsigned int i = 0; i < inlen;) {
    unsigned int len = in[i];
    if (i + 1 + len > inlen) break;
    i += 1 + len;
  }
  auto *server_alpn = static_cast<const std::vector<uint8_t> *>(arg);
  if (!server_alpn || server_alpn->empty()) {
    static const unsigned char default_alpn[] = {2, 'h', '3'};
    int ret =
        SSL_select_next_proto(const_cast<unsigned char **>(out), outlen,
                              default_alpn, sizeof(default_alpn), in, inlen);
    return (ret == OPENSSL_NPN_NEGOTIATED) ? SSL_TLSEXT_ERR_OK
                                           : SSL_TLSEXT_ERR_NOACK;
  }

  int ret = SSL_select_next_proto(const_cast<unsigned char **>(out), outlen,
                                  server_alpn->data(), server_alpn->size(), in,
                                  inlen);
  return (ret == OPENSSL_NPN_NEGOTIATED) ? SSL_TLSEXT_ERR_OK
                                         : SSL_TLSEXT_ERR_NOACK;
}

inline void SetQuicTransportParams(SSL *ssl) {
  auto *conn = static_cast<::cppquic::QuicConnection *>(SSL_get_app_data(ssl));
  if (!conn) return;

  std::vector<uint8_t> params;

  auto write_param = [](std::vector<uint8_t> &buf, uint64_t id, uint64_t val) {
    WriteVarInt(buf, id);
    std::vector<uint8_t> val_buf;
    WriteVarInt(val_buf, val);
    WriteVarInt(buf, val_buf.size());
    buf.insert(buf.end(), val_buf.begin(), val_buf.end());
  };

  // 1. original_destination_connection_id (0x00)
  if (conn->IsServer()) {
    const auto &orig_dcid = conn->GetOriginalDestinationConnectionId();
    if (!orig_dcid.IsZero()) {
      WriteVarInt(params, 0x00);
      WriteVarInt(params, orig_dcid.length);
      params.insert(params.end(), orig_dcid.data,
                    orig_dcid.data + orig_dcid.length);
    }
  }

  // 2. initial_source_connection_id (0x0f)
  const auto &local_cid = conn->GetLocalConnectionId();
  WriteVarInt(params, 0x0f);
  WriteVarInt(params, local_cid.length);
  params.insert(params.end(), local_cid.data,
                local_cid.data + local_cid.length);

  // 3. standard parameters
  write_param(params, 0x03, 1048576);  // initial_max_data
  write_param(params, 0x04, 1048576);  // initial_max_stream_data_bidi_local
  write_param(params, 0x05, 1048576);  // initial_max_stream_data_bidi_remote
  write_param(params, 0x06, 1048576);  // initial_max_stream_data_uni
  write_param(params, 0x07, 100);      // initial_max_streams_bidi
  write_param(params, 0x08, 100);      // initial_max_streams_uni
  write_param(params, 0x09, 3);        // ack_delay_exponent
  write_param(params, 0x0e, 2);        // active_connection_id_limit

  SSL_set_quic_transport_params(ssl, params.data(), params.size());
}

inline void QuicKeylogCallback(const SSL *ssl, const char *line) {
  auto *conn = static_cast<::cppquic::QuicConnection *>(SSL_get_app_data(ssl));
  if (conn) {
    conn->HandleKeylogLine(line);
  }
}

}  // namespace internal

// ============================================================================
// QUIC Server
// ============================================================================

/**
 * @brief A QUIC server that accepts connections on a bound port.
 *
 * Uses `UdpListener` internally for UDP transport.
 */
// ============================================================================
// PubSub Events
// ============================================================================

struct QuicConnectionEvent {
  std::shared_ptr<QuicConnection> connection;
  ConnectionState state;
};

struct QuicStreamDataEvent {
  std::shared_ptr<QuicConnection> connection;
  uint64_t stream_id;
  std::vector<uint8_t> data;
  bool fin;
};

// ============================================================================
// QuicServer
// ============================================================================

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
    SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);

    uint8_t ticket_key[48];
    if (RAND_bytes(ticket_key, sizeof(ticket_key)) == 1) {
      SSL_CTX_set_tlsext_ticket_keys(ssl_ctx_, ticket_key, sizeof(ticket_key));
    }
    SSL_CTX_set_keylog_callback(ssl_ctx_, internal::QuicKeylogCallback);
    SSL_CTX_set_quic_method(ssl_ctx_, &internal::quic_method);
    SSL_CTX_set_dh_auto(ssl_ctx_, 1);
    alpn_wire_ = internal::SerializeAlpnProtos({"h3"});
    SSL_CTX_set_alpn_select_cb(ssl_ctx_, internal::QuicAlpnSelectCallback,
                               &alpn_wire_);
    if (!internal::GenerateSelfSignedCert(ssl_ctx_)) {
      internal::Log(LogSeverity::Error, "QuicServer",
                    "Failed to generate self-signed certificate");
    }
  }

  void SetAlpnProtos(const std::vector<std::string> &protos) {
    alpn_wire_ = internal::SerializeAlpnProtos(protos);
    SSL_CTX_set_alpn_select_cb(ssl_ctx_, internal::QuicAlpnSelectCallback,
                               &alpn_wire_);
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
   * @brief Sets the handler for flow-control updates.
   */
  void SetFlowControlHandler(
      std::function<void(std::shared_ptr<QuicConnection>)> handler) {
    flow_control_handler_ = std::move(handler);
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
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
      throw std::runtime_error("QuicServer already started");
    }

    worker_pool_ = std::make_unique<cppasyncworker::WorkerPool>(
        2, 0, [this](const std::exception_ptr &ex) {
          try {
            if (ex) std::rethrow_exception(ex);
          } catch (const std::exception &e) {
            if (error_handler_) error_handler_(0, e.what());
          } catch (...) {
            if (error_handler_)
              error_handler_(0, "Unknown exception in worker pool");
          }
        });

    conn_sub_ = broker_.Subscribe<QuicConnectionEvent>("connection_events");
    event_worker_.AddSubscription(
        conn_sub_, [this](const QuicConnectionEvent &ev) {
          (void)worker_pool_->Enqueue([this, ev]() {
            if (ev.state == ConnectionState::Connected && connection_handler_) {
              connection_handler_(ev.connection);
            }
          });
        });

    stream_sub_ = broker_.Subscribe<QuicStreamDataEvent>("stream_data_events");
    event_worker_.AddSubscription(
        stream_sub_, [this](const QuicStreamDataEvent &ev) {
          (void)worker_pool_->Enqueue([this, ev]() {
            if (stream_data_handler_) {
              stream_data_handler_(ev.connection, ev.stream_id, ev.data,
                                   ev.fin);
            }
          });
        });

    event_worker_.SetTickCallback(std::chrono::milliseconds(10),
                                  [this]() { MaintenanceLoopTick(); });

    listener_.SetDataHandler([this](uint64_t session_id,
                                    const cppudpnet::PeerAddress &peer,
                                    const std::vector<uint8_t> &data) {
      auto packets = QuicPacket::SplitCoalescedPackets(data);
      for (const auto &pkt_bytes : packets) {
        HandleIncomingPacket(peer, pkt_bytes);
      }
    });

    event_worker_.Start();
    listener_.Start();
    internal::Log(LogSeverity::Info, "QuicServer", "Started");
  }

  /**
   * @brief Stops the QUIC server.
   */
  void Stop() {
    if (!running_.exchange(false)) {
      return;
    }

    event_worker_.Stop();
    listener_.Stop();

    if (worker_pool_) {
      worker_pool_.reset();
    }

    std::lock_guard<std::mutex> lock(connections_mtx_);
    connections_.clear();
    dcid_to_conn_.clear();

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
    total.bytes_sent = accum_bytes_sent_;
    total.bytes_received = accum_bytes_received_;
    total.packets_sent = accum_packets_sent_;
    total.packets_received = accum_packets_received_;
    total.streams_opened = accum_streams_opened_;
    total.streams_closed = accum_streams_closed_;
    total.retransmissions = accum_retransmissions_;
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
    std::shared_ptr<QuicConnection> conn;
    bool is_short = !data.empty() && !(data[0] & 0x80);

    {
      std::lock_guard<std::mutex> lock(connections_mtx_);
      if (is_short) {
        for (auto &[id, c] : connections_) {
          uint8_t len = c->GetLocalConnectionId().length;
          if (data.size() >= 1 + len) {
            ConnectionId candidate;
            candidate.length = len;
            std::memcpy(candidate.data, data.data() + 1, len);
            if (c->GetLocalConnectionId() == candidate) {
              conn = c;
              conn_id = candidate;
              break;
            }
          }
        }
      } else {
        if (QuicPacket::PeekConnectionId(data, conn_id)) {
          for (auto &[id, c] : connections_) {
            if (c->GetLocalConnectionId() == conn_id ||
                c->GetRemoteConnectionId() == conn_id) {
              conn = c;
              break;
            }
          }
          // Also check if conn_id matches a known client original DCID.
          // A nullptr entry means another thread is currently handling the
          // first copy of this Initial — skip this duplicate.
          if (!conn) {
            auto it = dcid_to_conn_.find(conn_id);
            if (it != dcid_to_conn_.end()) {
              conn = it->second;  // may be nullptr (in-progress guard)
              if (!conn) return;  // duplicate Initial, discard
            } else {
              // First time we see this DCID — reserve it to prevent races
              dcid_to_conn_[conn_id] = nullptr;
            }
          }
        }
      }
    }

    if (is_short && !conn) {
      return;
    }
    if (!is_short && conn_id.IsZero() &&
        !QuicPacket::PeekConnectionId(data, conn_id)) {
      return;
    }

    QuicPacket pkt;
    bool packet_recorded = false;
    if (conn) {
      bool was_buffered = false;
      if (!conn->DeserializePacket(data, pkt, was_buffered)) {
        if (!was_buffered) {
          internal::Log(LogSeverity::Warn, "QuicServer",
                        "Failed to deserialize packet from " + peer.ToString());
        }
        return;
      }
      conn->RecordReceivedPacket(pkt.packet_number, pkt.packet_type);
      packet_recorded = true;
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
      std::vector<uint8_t> temp_read_hp;
      std::vector<uint8_t> temp_write_key;
      std::vector<uint8_t> temp_write_iv;
      std::vector<uint8_t> temp_write_hp;
      internal::DeriveInitialKeys(conn_id, true, temp_read_key, temp_read_iv,
                                  temp_read_hp, temp_write_key, temp_write_iv,
                                  temp_write_hp);

      if (!QuicPacket::Deserialize(data, pkt, &temp_read_key, &temp_read_iv,
                                   &temp_read_hp)) {
        internal::Log(
            LogSeverity::Warn, "QuicServer",
            "Failed to deserialize Initial packet from " + peer.ToString());
        return;
      }
    }

    // Process frames
    for (const auto &frame : pkt.frames) {
      std::visit(
          [this, &peer, &pkt, &conn, &conn_id, &packet_recorded](auto &&f) {
            using T = std::decay_t<decltype(f)>;

            if constexpr (std::is_same_v<T, CryptoFrame>) {
              if (conn) {
                conn->Touch();
                auto pkts = conn->ProcessCrypto(
                    f.offset, f.data,
                    pkt.packet_type == 2 ? 2 : (pkt.packet_type == 0 ? 3 : 0));
                for (const auto &p_out : pkts) {
                  auto bytes = conn->SerializePacket(p_out);
                  conn->AddBytesSent(bytes.size());
                  listener_.Send(peer, bytes);
                }

                auto crypto_ctx = conn->GetCryptoContext();
                if (crypto_ctx && crypto_ctx->handshake_complete &&
                    conn->GetState() == ConnectionState::Handshaking) {
                  conn->SetState(ConnectionState::Connected);
                  internal::Log(LogSeverity::Info, "QuicServer",
                                "Handshake complete. Server ready.");
                  QuicConnectionEvent ev;
                  ev.connection = conn;
                  ev.state = ConnectionState::Connected;
                  broker_.Publish("connection_events", ev);

                  event_broker_.Publish<ConnectionEvent>(
                      "connection_events", {conn->GetLocalConnectionId(), peer,
                                            ConnectionState::Connected});

                  // Drain and replay any buffered raw 1-RTT packets now that
                  // 1-RTT keys are ready
                  auto pending = conn->DrainPending1RawPackets();
                  for (const auto &raw_pkt : pending) {
                    HandleIncomingPacket(peer, raw_pkt);
                  }
                }
              } else {
                // If conn doesn't exist, this is ClientHello (represented in
                // CryptoFrame)
                conn = HandleClientHello(peer, conn_id,
                                         pkt.source_connection_id, f);
                if (conn && !packet_recorded) {
                  conn->RecordReceivedPacket(pkt.packet_number,
                                             pkt.packet_type);
                  packet_recorded = true;
                }
              }
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
              if (conn) {
                conn->Touch();
                conn->AddBytesReceived(f.data.size());
                HandleStreamFrame(conn, f);
              }
            } else if constexpr (std::is_same_v<T, AckFrame>) {
              if (conn) {
                conn->Touch();
                conn->ProcessAck(f);
                SendPendingPackets(conn);
              }
            } else if constexpr (std::is_same_v<T, PingFrame>) {
              if (conn) {
                conn->Touch();
                SendAck(conn, pkt.packet_type);
              }
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
              if (conn) {
                conn->SetState(ConnectionState::Closed);
                RemoveConnection(conn->GetLocalConnectionId());
                QuicConnectionEvent ev;
                ev.connection = conn;
                ev.state = ConnectionState::Closed;
                broker_.Publish("connection_events", ev);

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
                conn->SetMaxSendData(f.max_data);
                conn->GenerateStreamPackets();
                SendPendingPackets(conn);
                if (flow_control_handler_) {
                  flow_control_handler_(conn);
                }
              }
            } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
              if (conn) {
                conn->Touch();
                auto stream = conn->GetStream(f.stream_id);
                if (stream) {
                  stream->SetMaxSendOffset(f.max_stream_data);
                  conn->GenerateStreamPackets();
                  SendPendingPackets(conn);
                  if (flow_control_handler_) {
                    flow_control_handler_(conn);
                  }
                }
              }
            }
          },
          frame);
    }
    if (conn) SendAck(conn, pkt.packet_type);
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
      dcid_to_conn_[dest_id] = conn;  // Map original client DCID to this conn
    }

    // Initial packet from client: level 0 (ssl_encryption_initial)
    auto pkts = conn->ProcessCrypto(cf.offset, cf.data, 0);
    for (const auto &pkt : pkts) {
      auto bytes = conn->SerializePacket(pkt);
      conn->AddBytesSent(bytes.size());
      listener_.Send(peer, bytes);
    }

    internal::Log(LogSeverity::Info, "QuicServer",
                  "New handshaking connection accepted");
    return conn;
  }

  void HandleStreamFrame(std::shared_ptr<QuicConnection> conn,
                         const StreamFrame &frame) {
    auto stream = conn->GetOrCreateStream(frame.stream_id);
    bool ok = stream->OnStreamFrame(frame);

    // Send ACK
    SendAck(conn, 0);

    std::vector<uint8_t> data;
    bool is_finished = false;
    if (ok && (stream_data_handler_ || conn->IsAutoFlowControlEnabled())) {
      data = stream->Read(0);
      is_finished = stream->IsFinished();
    }

    if (ok && (!data.empty() || is_finished)) {
      QuicStreamDataEvent ev;
      ev.connection = conn;
      ev.stream_id = frame.stream_id;
      ev.data = data;
      ev.fin = is_finished;
      broker_.Publish("stream_data_events", ev);
    }

    if (ok && conn->IsAutoFlowControlEnabled()) {
      if (!data.empty()) {
        conn->AddBytesRead(data.size());
      }
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

  void SendAck(std::shared_ptr<QuicConnection> conn, uint8_t packet_type) {
    auto ack = conn->GenerateAck(packet_type);
    if (ack.acknowledged_packets.empty()) return;
    std::vector<QuicFrame> frames;
    frames.push_back(std::move(ack));
    auto pkt = conn->CreatePacket(std::move(frames), packet_type);
    auto bytes = conn->SerializePacket(pkt);
    conn->AddBytesSent(bytes.size());
    listener_.Send(conn->GetPeer(), bytes);
  }

  void RemoveConnection(const ConnectionId &id) {
    std::lock_guard<std::mutex> lock(connections_mtx_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
      auto cs = it->second->GetStats();
      accum_bytes_sent_ += cs.bytes_sent;
      accum_bytes_received_ += cs.bytes_received;
      accum_packets_sent_ += cs.packets_sent;
      accum_packets_received_ += cs.packets_received;
      accum_streams_opened_ += cs.streams_opened;
      accum_streams_closed_ += cs.streams_closed;
      accum_retransmissions_ += cs.retransmissions;
      connections_.erase(it);
    }
  }

  void MaintenanceLoopTick() {
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
                      "Connection closed due to idle timeout");

        QuicConnectionEvent ev;
        ev.connection = conn;
        ev.state = ConnectionState::Closed;
        broker_.Publish("connection_events", ev);

        event_broker_.Publish<ConnectionEvent>(
            "connection_events", {conn->GetLocalConnectionId(), conn->GetPeer(),
                                  ConnectionState::Closed});

        RemoveConnection(conn->GetLocalConnectionId());
        continue;
      }

      // Process retransmissions with pacing
      auto retransmits = conn->GetRetransmissions();
      auto send_time = std::chrono::steady_clock::now();
      for (auto &pkt : retransmits) {
        PreciseSleepUntil(send_time);
        auto bytes = conn->SerializePacket(pkt);
        conn->AddBytesSent(bytes.size());
        listener_.Send(conn->GetPeer(), bytes);
        send_time += std::chrono::microseconds(100);
      }

      // Drain any pending packets that were blocked by congestion control
      SendPendingPackets(conn);
    }
  }

  SSL_CTX *ssl_ctx_ = nullptr;
  std::vector<uint8_t> alpn_wire_;
  cppudpnet::UdpListener listener_;
  cpppubsub::PubSub event_broker_;

  std::atomic<bool> running_{false};
  cpppubsub::PubSub broker_;
  cpppubsub::Worker event_worker_;
  std::unique_ptr<cppasyncworker::WorkerPool> worker_pool_;
  std::shared_ptr<cpppubsub::Subscriber<QuicConnectionEvent>> conn_sub_;
  std::shared_ptr<cpppubsub::Subscriber<QuicStreamDataEvent>> stream_sub_;

  mutable std::mutex connections_mtx_;
  std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>,
                     ConnectionIdHash>
      connections_;
  // Maps client's original Destination CID -> established connection
  // Needed to route retransmitted Initial packets to the same connection
  std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>,
                     ConnectionIdHash>
      dcid_to_conn_;

  std::function<void(std::shared_ptr<QuicConnection>)> connection_handler_;
  std::function<void(std::shared_ptr<QuicConnection>, uint64_t,
                     const std::vector<uint8_t> &, bool)>
      stream_data_handler_;
  std::function<void(int, const std::string &)> error_handler_;
  std::function<void(std::shared_ptr<QuicConnection>)> flow_control_handler_;

  // Accumulated historical stats from closed connections
  uint64_t accum_bytes_sent_ = 0;
  uint64_t accum_bytes_received_ = 0;
  uint64_t accum_packets_sent_ = 0;
  uint64_t accum_packets_received_ = 0;
  uint64_t accum_streams_opened_ = 0;
  uint64_t accum_streams_closed_ = 0;
  uint64_t accum_retransmissions_ = 0;

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
    SSL_CTX_set_quic_method(ssl_ctx_, &internal::quic_method);
    // Accept self-signed server certificates by default. Developers can supply
    // their own verified CA store via SSL_CTX_load_verify_locations if needed.
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
  }

  void SetAlpnProtos(const std::vector<std::string> &protos) {
    alpn_protos_ = protos;
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
   * @brief Sets the handler for flow-control updates.
   */
  void SetFlowControlHandler(std::function<void()> handler) {
    flow_control_handler_ = std::move(handler);
  }

  /**
   * @brief Starts the client's underlying transport.
   * @throws std::runtime_error if already started.
   */
  void Start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
      throw std::runtime_error("QuicClient already started");
    }

    worker_pool_ = std::make_unique<cppasyncworker::WorkerPool>(
        1, 0, [this](const std::exception_ptr &ex) {
          try {
            if (ex) std::rethrow_exception(ex);
          } catch (const std::exception &e) {
            if (error_handler_) error_handler_(0, e.what());
          } catch (...) {
            if (error_handler_)
              error_handler_(0, "Unknown exception in worker pool");
          }
        });

    stream_sub_ = broker_.Subscribe<QuicStreamDataEvent>("stream_data_events");
    event_worker_.AddSubscription(
        stream_sub_, [this](const QuicStreamDataEvent &ev) {
          (void)worker_pool_->Enqueue([this, ev]() {
            if (stream_data_handler_) {
              stream_data_handler_(ev.stream_id, ev.data, ev.fin);
            }
          });
        });

    event_worker_.SetTickCallback(std::chrono::milliseconds(10),
                                  [this]() { MaintenanceLoopTick(); });

    sender_.Bind(0);

    sender_.SetDataHandler([this](const cppudpnet::PeerAddress &peer,
                                  const std::vector<uint8_t> &data) {
      auto packets = QuicPacket::SplitCoalescedPackets(data);
      for (const auto &pkt_bytes : packets) {
        HandleIncomingPacket(peer, pkt_bytes);
      }
    });

    sender_.SetErrorHandler([this](int code, const std::string &msg) {
      internal::Log(LogSeverity::Error, "QuicClient",
                    msg + " (code: " + std::to_string(code) + ")");
    });

    event_worker_.Start();
    sender_.Start();

    internal::Log(LogSeverity::Info, "QuicClient",
                  "Started on port " + std::to_string(sender_.GetLocalPort()));
  }

  /**
   * @brief Stops the client.
   */
  void Stop() {
    if (!running_.exchange(false)) {
      return;
    }

    event_worker_.Stop();

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
        local_id, remote_id, server_address_, false, ssl_ctx_, ConnectionId{},
        alpn_protos_);
    connection_->SetCongestionControlAlgorithm(cc_algorithm_);
    connection_->SetAutoFlowControl(auto_flow_control_);
    connection_->SetState(ConnectionState::Handshaking);

    auto pkts = connection_->ProcessCrypto(0, {}, 0);
    for (const auto &pkt : pkts) {
      auto bytes = connection_->SerializePacket(pkt);
      connection_->AddBytesSent(bytes.size());
      sender_.Send(host, port, bytes);
    }

    internal::Log(
        LogSeverity::Info, "QuicClient",
        "Sending ClientHello to " + host + ":" + std::to_string(port));

    // Wait for handshake completion using PubSub selector
    auto sub = broker_.Subscribe<QuicConnectionEvent>("connection_events");
    cpppubsub::Selector selector;
    bool completed = false;
    selector.Add(sub, [&](const QuicConnectionEvent &ev) {
      if (ev.state == ConnectionState::Connected) {
        completed = true;
      }
    });

    auto start = std::chrono::steady_clock::now();
    while (!completed &&
           connection_->GetState() == ConnectionState::Handshaking) {
      auto elapsed = std::chrono::steady_clock::now() - start;
      auto rem = std::chrono::milliseconds(timeout_ms) -
                 std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
      if (rem.count() <= 0) break;
      selector.WaitFor(rem);
    }

    if (!completed || connection_->GetState() != ConnectionState::Connected) {
      if (connection_->GetState() == ConnectionState::Handshaking) {
        internal::Log(LogSeverity::Error, "QuicClient", "Handshake timed out");
        connection_->SetState(ConnectionState::Closed);
      }
      return false;
    }

    return true;
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
   * @brief Non-blocking backpressure check. Returns true if the stream has
   * enough flow-control budget to send @p bytes without blocking.
   *
   * Use this to implement application-level backpressure: if CanSendOnStream
   * returns false, the stream's flow-control window is exhausted and you
   * should wait for a MaxStreamData update before queuing more data.
   */
  bool CanSendOnStream(uint64_t stream_id, size_t bytes) const {
    if (!connection_) return false;
    auto stream = connection_->GetStream(stream_id);
    if (!stream) return false;

    // Check stream-level flow control
    if (stream->GetSendOffset() + bytes > stream->GetMaxSendOffset()) {
      return false;
    }

    // Check connection-level flow control
    if (connection_->GetTotalStreamBytesSent() + bytes >
        connection_->GetMaxSendData()) {
      return false;
    }

    return true;
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
    bool is_short = !data.empty() && !(data[0] & 0x80);
    if (is_short && connection_) {
      uint8_t len = connection_->GetLocalConnectionId().length;
      if (data.size() >= 1 + len) {
        conn_id.length = len;
        std::memcpy(conn_id.data, data.data() + 1, len);
      } else {
        return;
      }
    } else {
      if (!QuicPacket::PeekConnectionId(data, conn_id)) {
        return;
      }
    }

    QuicPacket pkt;
    if (connection_) {
      bool was_buffered = false;
      if (!connection_->DeserializePacket(data, pkt, was_buffered)) {
        if (was_buffered) return;  // Suppress warning, wait for replay
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
      connection_->RecordReceivedPacket(pkt.packet_number, pkt.packet_type);
    } else {
      // Derive Initial keys to decrypt Server Initial packet
      std::vector<uint8_t> temp_read_key;
      std::vector<uint8_t> temp_read_iv;
      std::vector<uint8_t> temp_read_hp;
      std::vector<uint8_t> temp_write_key;
      std::vector<uint8_t> temp_write_iv;
      std::vector<uint8_t> temp_write_hp;
      internal::DeriveInitialKeys(conn_id, false, temp_read_key, temp_read_iv,
                                  temp_read_hp, temp_write_key, temp_write_iv,
                                  temp_write_hp);

      if (!QuicPacket::Deserialize(data, pkt, &temp_read_key, &temp_read_iv,
                                   &temp_read_hp)) {
        internal::Log(LogSeverity::Warn, "QuicClient",
                      "Failed to deserialize Initial packet from server");
        return;
      }
      if (connection_) {
        connection_->RecordReceivedPacket(pkt.packet_number, pkt.packet_type);
      }
    }

    for (const auto &frame : pkt.frames) {
      std::visit(
          [this, &pkt, &peer](auto &&f) {
            using T = std::decay_t<decltype(f)>;

            if constexpr (std::is_same_v<T, CryptoFrame>) {
              if (connection_) {
                // Server source connection ID is updated in the connection only
                // during handshake
                if (connection_->GetState() == ConnectionState::Handshaking &&
                    !pkt.source_connection_id.IsZero()) {
                  connection_->SetRemoteConnectionId(pkt.source_connection_id);
                }

                auto pkts = connection_->ProcessCrypto(
                    f.offset, f.data,
                    pkt.packet_type == 2 ? 2 : (pkt.packet_type == 0 ? 3 : 0));
                for (const auto &pkt_out : pkts) {
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

                  QuicConnectionEvent ev;
                  ev.connection = connection_;
                  ev.state = ConnectionState::Connected;
                  broker_.Publish("connection_events", ev);

                  // Drain and replay any buffered raw 1-RTT packets now that
                  // 1-RTT keys are ready
                  auto pending = connection_->DrainPending1RawPackets();
                  for (const auto &raw_pkt : pending) {
                    HandleIncomingPacket(peer, raw_pkt);
                  }
                }
              }
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
              if (connection_) {
                connection_->Touch();
                connection_->AddBytesReceived(f.data.size());

                auto stream = connection_->GetOrCreateStream(f.stream_id);
                bool ok = stream->OnStreamFrame(f);

                // Send ACK
                SendAck(0);

                std::vector<uint8_t> data;
                bool is_finished = false;
                if (ok && (stream_data_handler_ ||
                           connection_->IsAutoFlowControlEnabled())) {
                  data = stream->Read(0);
                  is_finished = stream->IsFinished();
                }

                if (ok && (!data.empty() || is_finished)) {
                  QuicStreamDataEvent ev;
                  ev.connection = connection_;
                  ev.stream_id = f.stream_id;
                  ev.data = data;
                  ev.fin = is_finished;
                  broker_.Publish("stream_data_events", ev);
                }

                if (ok && connection_->IsAutoFlowControlEnabled()) {
                  if (!data.empty()) {
                    connection_->AddBytesRead(data.size());
                  }
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
                connection_->Touch();
                connection_->ProcessAck(f);
                SendPendingPackets();
              }
            } else if constexpr (std::is_same_v<T, PingFrame>) {
              if (connection_) {
                connection_->Touch();
                SendAck(pkt.packet_type);
              }
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
              if (connection_) {
                connection_->SetState(ConnectionState::Closed);
                internal::Log(LogSeverity::Info, "QuicClient",
                              "Connection closed by server");
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
                connection_->SetMaxSendData(f.max_data);
                connection_->GenerateStreamPackets();
                SendPendingPackets();
                if (flow_control_handler_) {
                  (void)worker_pool_->Enqueue(
                      [this]() { flow_control_handler_(); });
                }
              }
            } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
              if (connection_) {
                connection_->Touch();
                auto stream = connection_->GetStream(f.stream_id);
                if (stream) {
                  stream->SetMaxSendOffset(f.max_stream_data);
                  connection_->GenerateStreamPackets();
                  SendPendingPackets();
                  if (flow_control_handler_) {
                    (void)worker_pool_->Enqueue(
                        [this]() { flow_control_handler_(); });
                  }
                }
              }
            } else if constexpr (std::is_same_v<T, HandshakeDoneFrame>) {
              if (connection_) {
                connection_->Touch();
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

  void SendAck(uint8_t packet_type) {
    if (!connection_) return;
    auto ack = connection_->GenerateAck(packet_type);
    if (ack.acknowledged_packets.empty()) return;
    std::vector<QuicFrame> frames;
    frames.push_back(std::move(ack));
    auto pkt = connection_->CreatePacket(std::move(frames), packet_type);
    auto bytes = connection_->SerializePacket(pkt);
    connection_->AddBytesSent(bytes.size());
    sender_.Send(server_address_, bytes);
  }

  void MaintenanceLoopTick() {
    if (!connection_ ||
        (connection_->GetState() != ConnectionState::Connected &&
         connection_->GetState() != ConnectionState::Handshaking)) {
      return;
    }

    // Process retransmissions with pacing
    auto retransmits = connection_->GetRetransmissions();
    auto send_time = std::chrono::steady_clock::now();
    for (auto &pkt : retransmits) {
      PreciseSleepUntil(send_time);
      auto bytes = connection_->SerializePacket(pkt);
      connection_->AddBytesSent(bytes.size());
      sender_.Send(server_address_, bytes);
      send_time += std::chrono::microseconds(100);
    }

    // Drain any pending packets that were blocked by congestion control
    SendPendingPackets();
  }

  SSL_CTX *ssl_ctx_ = nullptr;
  std::vector<std::string> alpn_protos_ = {"h3"};
  cppudpnet::UdpSender sender_;

  std::atomic<bool> running_{false};

  cpppubsub::PubSub broker_;
  cpppubsub::Worker event_worker_;
  std::unique_ptr<cppasyncworker::WorkerPool> worker_pool_;
  std::shared_ptr<cpppubsub::Subscriber<QuicStreamDataEvent>> stream_sub_;

  cppudpnet::PeerAddress server_address_;
  std::shared_ptr<QuicConnection> connection_;

  std::function<void(uint64_t, const std::vector<uint8_t> &, bool)>
      stream_data_handler_;
  std::function<void(int, const std::string &)> error_handler_;
  std::function<void()> flow_control_handler_;

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
    poll_cv_.notify_all();
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

      // Wait for poll_interval_, but wake immediately when destructor signals
      std::unique_lock<std::mutex> lock(poll_cv_mtx_);
      poll_cv_.wait_for(lock, poll_interval_,
                        [this] { return !running_.load(); });
    }
  }

  T &target_;
  std::chrono::milliseconds poll_interval_;
  std::atomic<bool> running_{false};
  std::thread thread_;
  std::mutex poll_cv_mtx_;
  std::condition_variable poll_cv_;

  mutable std::mutex mtx_;
  std::deque<Sample> samples_;
  double send_throughput_ = 0.0;
  double recv_throughput_ = 0.0;
};

}  // namespace cppquic
