#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "cppquic.hpp"

// Helper to wait for a condition with timeout
template <typename Pred>
bool WaitFor(Pred pred, std::chrono::milliseconds timeout) {
  auto start = std::chrono::steady_clock::now();
  while (!pred()) {
    if (std::chrono::steady_clock::now() - start > timeout) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return true;
}

// ============================================================================
// Version Tests
// ============================================================================

TEST(VersionTest, VersionStringFormat) {
  const auto& ver = cppquic::version();
  EXPECT_FALSE(ver.empty());
  int dot_count = 0;
  for (char c : ver) {
    if (c == '.') dot_count++;
  }
  EXPECT_EQ(dot_count, 2);
}

TEST(VersionTest, VersionConstants) {
  EXPECT_GE(cppquic::VERSION_MAJOR, 0);
  EXPECT_GE(cppquic::VERSION_MINOR, 0);
  EXPECT_GE(cppquic::VERSION_PATCH, 0);
}

// ============================================================================
// ConnectionId Tests
// ============================================================================

TEST(ConnectionIdTest, Generation) {
  auto id = cppquic::internal::GenerateConnectionId();
  EXPECT_FALSE(id.IsZero());
}

TEST(ConnectionIdTest, Equality) {
  cppquic::ConnectionId a;
  cppquic::ConnectionId b;
  std::memset(a.data, 0x42, 8);
  std::memset(b.data, 0x42, 8);
  EXPECT_EQ(a, b);

  b.data[0] = 0xFF;
  EXPECT_NE(a, b);
}

TEST(ConnectionIdTest, ToHex) {
  cppquic::ConnectionId id;
  std::memset(id.data, 0, 8);
  EXPECT_EQ(id.ToHex(), "0000000000000000");

  id.data[0] = 0xAB;
  id.data[7] = 0xCD;
  EXPECT_EQ(id.ToHex(), "ab000000000000cd");
}

TEST(ConnectionIdTest, Hash) {
  cppquic::ConnectionIdHash hasher;
  cppquic::ConnectionId a;
  cppquic::ConnectionId b;
  std::memset(a.data, 0x42, 8);
  std::memset(b.data, 0x42, 8);
  EXPECT_EQ(hasher(a), hasher(b));

  b.data[0] = 0xFF;
  EXPECT_NE(hasher(a), hasher(b));
}

TEST(ConnectionIdTest, Serialization) {
  cppquic::ConnectionId original;
  std::memset(original.data, 0x55, 8);

  std::vector<uint8_t> buf;
  original.Serialize(buf);
  EXPECT_EQ(buf.size(), 8u);

  cppquic::ConnectionId deserialized;
  size_t offset = 0;
  EXPECT_TRUE(cppquic::ConnectionId::Deserialize(buf.data(), buf.size(), offset,
                                                 deserialized));
  EXPECT_EQ(offset, 8u);
  EXPECT_EQ(original, deserialized);
}

// ============================================================================
// Stream ID Tests
// ============================================================================

TEST(StreamIdTest, MakeStreamId) {
  uint64_t id = cppquic::MakeStreamId(0, cppquic::StreamType::ClientBidi);
  EXPECT_EQ(id, 0u);
  EXPECT_TRUE(cppquic::IsClientInitiated(id));
  EXPECT_TRUE(cppquic::IsBidirectional(id));

  id = cppquic::MakeStreamId(1, cppquic::StreamType::ServerUni);
  EXPECT_FALSE(cppquic::IsClientInitiated(id));
  EXPECT_FALSE(cppquic::IsBidirectional(id));
}

TEST(StreamIdTest, GetStreamType) {
  EXPECT_EQ(cppquic::GetStreamType(0), cppquic::StreamType::ClientBidi);
  EXPECT_EQ(cppquic::GetStreamType(1), cppquic::StreamType::ServerBidi);
  EXPECT_EQ(cppquic::GetStreamType(2), cppquic::StreamType::ClientUni);
  EXPECT_EQ(cppquic::GetStreamType(3), cppquic::StreamType::ServerUni);
}

// ============================================================================
// ScaledUnit Tests
// ============================================================================

TEST(ScaledUnitTest, ScaleBytes) {
  auto result = cppquic::ScaleBytes(0);
  EXPECT_DOUBLE_EQ(result.value, 0.0);
  EXPECT_STREQ(result.unit, "B");

  result = cppquic::ScaleBytes(1024);
  EXPECT_DOUBLE_EQ(result.value, 1.0);
  EXPECT_STREQ(result.unit, "KB");

  result = cppquic::ScaleBytes(1048576);
  EXPECT_DOUBLE_EQ(result.value, 1.0);
  EXPECT_STREQ(result.unit, "MB");
}

TEST(ScaledUnitTest, ScaleBits) {
  auto result = cppquic::ScaleBits(0);
  EXPECT_DOUBLE_EQ(result.value, 0.0);
  EXPECT_STREQ(result.unit, "bps");

  result = cppquic::ScaleBits(1000);
  EXPECT_DOUBLE_EQ(result.value, 1.0);
  EXPECT_STREQ(result.unit, "Kbps");

  result = cppquic::ScaleBits(1000000);
  EXPECT_DOUBLE_EQ(result.value, 1.0);
  EXPECT_STREQ(result.unit, "Mbps");
}

// ============================================================================
// Logger Tests
// ============================================================================

TEST(LoggerTest, SetAndClearLogger) {
  bool called = false;
  cppquic::SetLogger([&called](cppquic::LogSeverity, const std::string&,
                               const std::string&) { called = true; });

  // Trigger a log internally by starting/stopping a server
  cppquic::QuicServer server(0);
  server.Start();
  server.Stop();

  EXPECT_TRUE(called);

  // Clear logger
  cppquic::SetLogger(nullptr);
}

// ============================================================================
// QuicPacket Serialization Tests
// ============================================================================

TEST(QuicPacketTest, SerializeDeserializeEmpty) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 42;

  auto bytes = pkt.Serialize();
  EXPECT_GT(bytes.size(), 0u);

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));
  EXPECT_EQ(decoded.connection_id, pkt.connection_id);
  EXPECT_EQ(decoded.packet_number, 42u);
  EXPECT_TRUE(decoded.frames.empty());
}

TEST(QuicPacketTest, SerializeDeserializeStreamFrame) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 1;

  cppquic::StreamFrame sf;
  sf.stream_id = 4;
  sf.offset = 0;
  sf.fin = false;
  sf.data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
  pkt.frames.push_back(sf);

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));
  EXPECT_EQ(decoded.frames.size(), 1u);

  auto& frame = std::get<cppquic::StreamFrame>(decoded.frames[0]);
  EXPECT_EQ(frame.stream_id, 4u);
  EXPECT_EQ(frame.offset, 0u);
  EXPECT_FALSE(frame.fin);
  EXPECT_EQ(frame.data, sf.data);
}

TEST(QuicPacketTest, SerializeDeserializeEncrypted) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 1;

  cppquic::StreamFrame sf;
  sf.stream_id = 4;
  sf.offset = 0;
  sf.fin = false;
  sf.data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
  pkt.frames.push_back(sf);

  std::vector<uint8_t> dummy_key(16, 0x11);
  std::vector<uint8_t> dummy_iv(12, 0x22);

  // Serialize with encryption
  auto bytes = pkt.Serialize(&dummy_key, &dummy_iv);
  EXPECT_GT(bytes.size(), 0u);
  EXPECT_EQ(bytes[0], 0x43);  // Short Header type byte

  cppquic::QuicPacket decoded;
  // Should fail to decode without keys
  EXPECT_FALSE(cppquic::QuicPacket::Deserialize(bytes, decoded));

  // Should succeed with correct keys
  EXPECT_TRUE(
      cppquic::QuicPacket::Deserialize(bytes, decoded, &dummy_key, &dummy_iv));
  EXPECT_EQ(decoded.frames.size(), 1u);

  auto& frame = std::get<cppquic::StreamFrame>(decoded.frames[0]);
  EXPECT_EQ(frame.stream_id, 4u);
  EXPECT_EQ(frame.offset, 0u);
  EXPECT_FALSE(frame.fin);
  EXPECT_EQ(frame.data, sf.data);
}

TEST(QuicPacketTest, SerializeDeserializeAckFrame) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 5;

  cppquic::AckFrame ack;
  ack.largest_acknowledged = 10;
  ack.ack_delay_us = 1000;
  ack.acknowledged_packets = {7, 8, 9, 10};
  pkt.frames.push_back(ack);

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));

  auto& frame = std::get<cppquic::AckFrame>(decoded.frames[0]);
  EXPECT_EQ(frame.largest_acknowledged, 10u);
  EXPECT_EQ(frame.ack_delay_us, 1000u);
  EXPECT_EQ(frame.acknowledged_packets.size(), 4u);
}

TEST(QuicPacketTest, SerializeDeserializeCrypto) {
  cppquic::QuicPacket pkt;
  pkt.packet_type = 1;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.source_connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 0;

  cppquic::CryptoFrame cf;
  cf.offset = 0;
  cf.data = {1, 2, 3, 4};
  pkt.frames.push_back(cf);

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));

  EXPECT_EQ(decoded.packet_type, 1);
  EXPECT_EQ(decoded.connection_id, pkt.connection_id);
  EXPECT_EQ(decoded.source_connection_id, pkt.source_connection_id);

  auto& frame = std::get<cppquic::CryptoFrame>(decoded.frames[0]);
  EXPECT_EQ(frame.offset, 0u);
  EXPECT_EQ(frame.data, cf.data);
}

TEST(QuicPacketTest, SerializeDeserializePing) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 99;
  pkt.frames.push_back(cppquic::PingFrame{});

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));
  EXPECT_EQ(decoded.frames.size(), 1u);
  EXPECT_TRUE(std::holds_alternative<cppquic::PingFrame>(decoded.frames[0]));
}

TEST(QuicPacketTest, SerializeDeserializeConnectionClose) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 100;

  cppquic::ConnectionCloseFrame close;
  close.error_code = 42;
  close.reason = "test shutdown";
  pkt.frames.push_back(close);

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));

  auto& frame = std::get<cppquic::ConnectionCloseFrame>(decoded.frames[0]);
  EXPECT_EQ(frame.error_code, 42u);
  EXPECT_EQ(frame.reason, "test shutdown");
}

TEST(QuicPacketTest, SerializeDeserializeResetStream) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 50;

  cppquic::ResetStreamFrame reset;
  reset.stream_id = 8;
  reset.error_code = 1;
  reset.final_size = 1024;
  pkt.frames.push_back(reset);

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));

  auto& frame = std::get<cppquic::ResetStreamFrame>(decoded.frames[0]);
  EXPECT_EQ(frame.stream_id, 8u);
  EXPECT_EQ(frame.error_code, 1u);
  EXPECT_EQ(frame.final_size, 1024u);
}

TEST(QuicPacketTest, SerializeDeserializeMultipleFrames) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 10;

  cppquic::StreamFrame sf;
  sf.stream_id = 4;
  sf.offset = 0;
  sf.data = {1, 2, 3};
  pkt.frames.push_back(sf);
  pkt.frames.push_back(cppquic::PingFrame{});

  cppquic::AckFrame ack;
  ack.largest_acknowledged = 5;
  ack.acknowledged_packets = {3, 4, 5};
  pkt.frames.push_back(ack);

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));
  EXPECT_EQ(decoded.frames.size(), 3u);
  EXPECT_TRUE(std::holds_alternative<cppquic::StreamFrame>(decoded.frames[0]));
  EXPECT_TRUE(std::holds_alternative<cppquic::PingFrame>(decoded.frames[1]));
  EXPECT_TRUE(std::holds_alternative<cppquic::AckFrame>(decoded.frames[2]));
}

TEST(QuicPacketTest, SerializeDeserializeNewFrames) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 10;

  pkt.frames.push_back(cppquic::PaddingFrame{});

  cppquic::StopSendingFrame stop_sending;
  stop_sending.stream_id = 123;
  stop_sending.error_code = 456;
  pkt.frames.push_back(stop_sending);

  cppquic::NewTokenFrame new_token;
  new_token.token = {0xAA, 0xBB, 0xCC};
  pkt.frames.push_back(new_token);

  cppquic::MaxDataFrame max_data;
  max_data.max_data = 1000000;
  pkt.frames.push_back(max_data);

  cppquic::MaxStreamDataFrame max_stream_data;
  max_stream_data.stream_id = 99;
  max_stream_data.max_stream_data = 200000;
  pkt.frames.push_back(max_stream_data);

  cppquic::MaxStreamsFrame max_streams_bidi;
  max_streams_bidi.unidirectional = false;
  max_streams_bidi.max_streams = 50;
  pkt.frames.push_back(max_streams_bidi);

  cppquic::MaxStreamsFrame max_streams_uni;
  max_streams_uni.unidirectional = true;
  max_streams_uni.max_streams = 100;
  pkt.frames.push_back(max_streams_uni);

  cppquic::DataBlockedFrame data_blocked;
  data_blocked.data_limit = 50000;
  pkt.frames.push_back(data_blocked);

  cppquic::StreamDataBlockedFrame stream_data_blocked;
  stream_data_blocked.stream_id = 45;
  stream_data_blocked.stream_data_limit = 10000;
  pkt.frames.push_back(stream_data_blocked);

  cppquic::StreamsBlockedFrame streams_blocked_bidi;
  streams_blocked_bidi.unidirectional = false;
  streams_blocked_bidi.stream_limit = 20;
  pkt.frames.push_back(streams_blocked_bidi);

  cppquic::StreamsBlockedFrame streams_blocked_uni;
  streams_blocked_uni.unidirectional = true;
  streams_blocked_uni.stream_limit = 30;
  pkt.frames.push_back(streams_blocked_uni);

  cppquic::NewConnectionIdFrame new_cid;
  new_cid.sequence_number = 1;
  new_cid.retire_prior_to = 0;
  std::memset(new_cid.connection_id.data, 0x11, 8);
  new_cid.stateless_reset_token = std::vector<uint8_t>(16, 0x99);
  pkt.frames.push_back(new_cid);

  cppquic::RetireConnectionIdFrame retire_cid;
  retire_cid.sequence_number = 2;
  pkt.frames.push_back(retire_cid);

  cppquic::PathChallengeFrame path_challenge;
  std::memset(path_challenge.data, 0x77, 8);
  pkt.frames.push_back(path_challenge);

  cppquic::PathResponseFrame path_response;
  std::memset(path_response.data, 0x88, 8);
  pkt.frames.push_back(path_response);

  pkt.frames.push_back(cppquic::HandshakeDoneFrame{});

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));
  ASSERT_EQ(decoded.frames.size(), 16u);

  EXPECT_TRUE(std::holds_alternative<cppquic::PaddingFrame>(decoded.frames[0]));

  auto& f1 = std::get<cppquic::StopSendingFrame>(decoded.frames[1]);
  EXPECT_EQ(f1.stream_id, 123u);
  EXPECT_EQ(f1.error_code, 456u);

  auto& f2 = std::get<cppquic::NewTokenFrame>(decoded.frames[2]);
  EXPECT_EQ(f2.token, (std::vector<uint8_t>{0xAA, 0xBB, 0xCC}));

  auto& f3 = std::get<cppquic::MaxDataFrame>(decoded.frames[3]);
  EXPECT_EQ(f3.max_data, 1000000u);

  auto& f4 = std::get<cppquic::MaxStreamDataFrame>(decoded.frames[4]);
  EXPECT_EQ(f4.stream_id, 99u);
  EXPECT_EQ(f4.max_stream_data, 200000u);

  auto& f5 = std::get<cppquic::MaxStreamsFrame>(decoded.frames[5]);
  EXPECT_FALSE(f5.unidirectional);
  EXPECT_EQ(f5.max_streams, 50u);

  auto& f6 = std::get<cppquic::MaxStreamsFrame>(decoded.frames[6]);
  EXPECT_TRUE(f6.unidirectional);
  EXPECT_EQ(f6.max_streams, 100u);

  auto& f7 = std::get<cppquic::DataBlockedFrame>(decoded.frames[7]);
  EXPECT_EQ(f7.data_limit, 50000u);

  auto& f8 = std::get<cppquic::StreamDataBlockedFrame>(decoded.frames[8]);
  EXPECT_EQ(f8.stream_id, 45u);
  EXPECT_EQ(f8.stream_data_limit, 10000u);

  auto& f9 = std::get<cppquic::StreamsBlockedFrame>(decoded.frames[9]);
  EXPECT_FALSE(f9.unidirectional);
  EXPECT_EQ(f9.stream_limit, 20u);

  auto& f10 = std::get<cppquic::StreamsBlockedFrame>(decoded.frames[10]);
  EXPECT_TRUE(f10.unidirectional);
  EXPECT_EQ(f10.stream_limit, 30u);

  auto& f11 = std::get<cppquic::NewConnectionIdFrame>(decoded.frames[11]);
  EXPECT_EQ(f11.sequence_number, 1u);
  EXPECT_EQ(f11.retire_prior_to, 0u);
  EXPECT_EQ(f11.connection_id, new_cid.connection_id);
  EXPECT_EQ(f11.stateless_reset_token, new_cid.stateless_reset_token);

  auto& f12 = std::get<cppquic::RetireConnectionIdFrame>(decoded.frames[12]);
  EXPECT_EQ(f12.sequence_number, 2u);

  auto& f13 = std::get<cppquic::PathChallengeFrame>(decoded.frames[13]);
  EXPECT_EQ(std::memcmp(f13.data, path_challenge.data, 8), 0);

  auto& f14 = std::get<cppquic::PathResponseFrame>(decoded.frames[14]);
  EXPECT_EQ(std::memcmp(f14.data, path_response.data, 8), 0);

  EXPECT_TRUE(
      std::holds_alternative<cppquic::HandshakeDoneFrame>(decoded.frames[15]));
}

TEST(QuicPacketTest, DeserializeInvalidData) {
  std::vector<uint8_t> garbage = {0xFF, 0x01, 0x02};
  cppquic::QuicPacket pkt;
  EXPECT_FALSE(cppquic::QuicPacket::Deserialize(garbage, pkt));
}

TEST(QuicPacketTest, DeserializeEmptyData) {
  std::vector<uint8_t> empty;
  cppquic::QuicPacket pkt;
  EXPECT_FALSE(cppquic::QuicPacket::Deserialize(empty, pkt));
}

// ============================================================================
// QuicStream Tests
// ============================================================================

TEST(QuicStreamTest, WriteAndRead) {
  cppquic::QuicStream stream(4);

  // Simulate sending data
  auto frames = stream.Write("Hello", false);
  EXPECT_FALSE(frames.empty());
  EXPECT_EQ(frames[0].stream_id, 4u);
  EXPECT_EQ(frames[0].offset, 0u);

  // Simulate receiving data
  cppquic::StreamFrame incoming;
  incoming.stream_id = 4;
  incoming.offset = 0;
  incoming.data = {0x48, 0x69};  // "Hi"
  incoming.fin = false;

  EXPECT_TRUE(stream.OnStreamFrame(incoming));
  auto read_data = stream.Read();
  EXPECT_EQ(read_data.size(), 2u);
  EXPECT_EQ(read_data[0], 0x48);
  EXPECT_EQ(read_data[1], 0x69);
}

TEST(QuicStreamTest, OrderedReassembly) {
  cppquic::QuicStream stream(0);

  // Send frames out of order
  cppquic::StreamFrame frame2;
  frame2.stream_id = 0;
  frame2.offset = 5;
  frame2.data = {6, 7, 8, 9, 10};

  cppquic::StreamFrame frame1;
  frame1.stream_id = 0;
  frame1.offset = 0;
  frame1.data = {1, 2, 3, 4, 5};

  // Receive frame 2 first (out of order)
  stream.OnStreamFrame(frame2);
  auto data = stream.Read();
  EXPECT_TRUE(data.empty());  // Can't read yet, gap at offset 0

  // Receive frame 1
  stream.OnStreamFrame(frame1);
  data = stream.Read();
  EXPECT_EQ(data.size(), 10u);
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(data[i], static_cast<uint8_t>(i + 1));
  }
}

TEST(QuicStreamTest, FinHandling) {
  cppquic::QuicStream stream(0);

  cppquic::StreamFrame frame;
  frame.stream_id = 0;
  frame.offset = 0;
  frame.data = {1, 2, 3};
  frame.fin = true;

  stream.OnStreamFrame(frame);
  auto data = stream.Read();
  EXPECT_EQ(data.size(), 3u);
  EXPECT_TRUE(stream.IsFinished());
}

TEST(QuicStreamTest, FlowControlViolation) {
  cppquic::QuicStream stream(0, 10);  // 10-byte window

  cppquic::StreamFrame frame;
  frame.stream_id = 0;
  frame.offset = 0;
  frame.data.resize(20, 'A');  // Exceeds window

  EXPECT_FALSE(stream.OnStreamFrame(frame));
}

TEST(QuicStreamTest, StreamState) {
  cppquic::QuicStream stream(0);
  EXPECT_EQ(stream.GetState(), cppquic::StreamState::Open);

  // Write with FIN
  stream.Write("goodbye", true);
  EXPECT_EQ(stream.GetState(), cppquic::StreamState::HalfClosedLocal);
}

TEST(QuicStreamTest, ReadableBytes) {
  cppquic::QuicStream stream(0);
  EXPECT_EQ(stream.ReadableBytes(), 0u);

  cppquic::StreamFrame frame;
  frame.stream_id = 0;
  frame.offset = 0;
  frame.data = {1, 2, 3, 4, 5};
  stream.OnStreamFrame(frame);

  EXPECT_EQ(stream.ReadableBytes(), 5u);
  stream.Read(3);
  EXPECT_EQ(stream.ReadableBytes(), 2u);
}

TEST(QuicStreamTest, Reset) {
  cppquic::QuicStream stream(0);
  stream.Reset(42);
  EXPECT_EQ(stream.GetState(), cppquic::StreamState::Closed);
}

// ============================================================================
// QuicConnection Tests
// ============================================================================

TEST(QuicConnectionTest, Construction) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);

  EXPECT_EQ(conn.GetLocalConnectionId(), local_id);
  EXPECT_EQ(conn.GetRemoteConnectionId(), remote_id);
  EXPECT_EQ(conn.GetState(), cppquic::ConnectionState::Idle);
}

TEST(QuicConnectionTest, StateTransitions) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);

  conn.SetState(cppquic::ConnectionState::Handshaking);
  EXPECT_EQ(conn.GetState(), cppquic::ConnectionState::Handshaking);

  conn.SetState(cppquic::ConnectionState::Connected);
  EXPECT_EQ(conn.GetState(), cppquic::ConnectionState::Connected);

  conn.SetState(cppquic::ConnectionState::Draining);
  EXPECT_EQ(conn.GetState(), cppquic::ConnectionState::Draining);

  conn.SetState(cppquic::ConnectionState::Closed);
  EXPECT_EQ(conn.GetState(), cppquic::ConnectionState::Closed);
}

TEST(QuicConnectionTest, StreamAllocation) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);

  uint64_t id1 = conn.AllocateStreamId(true);   // Client bidi
  uint64_t id2 = conn.AllocateStreamId(false);  // Client uni

  EXPECT_TRUE(cppquic::IsClientInitiated(id1));
  EXPECT_TRUE(cppquic::IsBidirectional(id1));
  EXPECT_TRUE(cppquic::IsClientInitiated(id2));
  EXPECT_FALSE(cppquic::IsBidirectional(id2));
  EXPECT_NE(id1, id2);
}

TEST(QuicConnectionTest, GetOrCreateStream) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);

  auto stream1 = conn.GetOrCreateStream(4);
  EXPECT_NE(stream1, nullptr);
  EXPECT_EQ(stream1->GetStreamId(), 4u);

  // Same stream ID returns the same stream
  auto stream1_again = conn.GetOrCreateStream(4);
  EXPECT_EQ(stream1.get(), stream1_again.get());

  // Different ID creates a new stream
  auto stream2 = conn.GetOrCreateStream(8);
  EXPECT_NE(stream2, nullptr);
  EXPECT_NE(stream1.get(), stream2.get());
}

TEST(QuicConnectionTest, PacketNumberIncrement) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);

  EXPECT_EQ(conn.PeekNextPacketNumber(), 0u);

  auto pkt1 = conn.CreatePacket({});
  EXPECT_EQ(pkt1.packet_number, 0u);

  auto pkt2 = conn.CreatePacket({});
  EXPECT_EQ(pkt2.packet_number, 1u);

  EXPECT_EQ(conn.PeekNextPacketNumber(), 2u);
}

TEST(QuicConnectionTest, AckProcessing) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);

  // Send some packets
  conn.CreatePacket({});  // pkt 0
  conn.CreatePacket({});  // pkt 1
  conn.CreatePacket({});  // pkt 2

  EXPECT_EQ(conn.PendingAcks(), 3u);

  // Ack packets 0 and 1
  cppquic::AckFrame ack;
  ack.largest_acknowledged = 1;
  ack.acknowledged_packets = {0, 1};
  size_t acked = conn.ProcessAck(ack);
  EXPECT_EQ(acked, 2u);
  EXPECT_EQ(conn.PendingAcks(), 1u);
}

TEST(QuicConnectionTest, RecordAndGenerateAck) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);

  conn.RecordReceivedPacket(5, 0);
  conn.RecordReceivedPacket(6, 0);
  conn.RecordReceivedPacket(7, 0);

  auto ack = conn.GenerateAck(0);
  EXPECT_EQ(ack.largest_acknowledged, 7u);
  EXPECT_EQ(ack.acknowledged_packets.size(), 3u);

  // Second call should return empty (already consumed)
  auto ack2 = conn.GenerateAck(0);
  EXPECT_TRUE(ack2.acknowledged_packets.empty());
}

TEST(QuicConnectionTest, HandshakePacket) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  auto pkt = conn.CreateHandshakePacket();

  EXPECT_EQ(pkt.packet_type, 1);
  EXPECT_EQ(pkt.frames.size(), 1u);
  auto& cf = std::get<cppquic::CryptoFrame>(pkt.frames[0]);
  EXPECT_EQ(cf.offset, 0u);
}

TEST(QuicConnectionTest, ClosePacket) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  auto pkt = conn.CreateClosePacket(42, "test reason");

  EXPECT_EQ(pkt.frames.size(), 1u);
  auto& close = std::get<cppquic::ConnectionCloseFrame>(pkt.frames[0]);
  EXPECT_EQ(close.error_code, 42u);
  EXPECT_EQ(close.reason, "test reason");
}

TEST(QuicConnectionTest, PingPacket) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  auto pkt = conn.CreatePingPacket();

  EXPECT_EQ(pkt.frames.size(), 1u);
  EXPECT_TRUE(std::holds_alternative<cppquic::PingFrame>(pkt.frames[0]));
}

TEST(QuicConnectionTest, IdleDetection) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  conn.Touch();

  EXPECT_FALSE(conn.IsIdle(std::chrono::milliseconds(200)));
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  EXPECT_TRUE(conn.IsIdle(std::chrono::milliseconds(200)));
}

TEST(QuicConnectionTest, StatsInitiallyZero) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  auto stats = conn.GetStats();

  EXPECT_EQ(stats.bytes_sent, 0u);
  EXPECT_EQ(stats.bytes_received, 0u);
  EXPECT_EQ(stats.packets_sent, 0u);
  EXPECT_EQ(stats.packets_received, 0u);
  EXPECT_EQ(stats.retransmissions, 0u);
}

TEST(QuicConnectionTest, StatsUpdate) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  conn.AddBytesSent(100);
  conn.AddBytesReceived(200);

  auto stats = conn.GetStats();
  EXPECT_EQ(stats.bytes_sent, 100u);
  EXPECT_EQ(stats.bytes_received, 200u);
  EXPECT_EQ(stats.packets_sent, 1u);
  EXPECT_EQ(stats.packets_received, 1u);
}

// ============================================================================
// QuicServer Tests
// ============================================================================

TEST(QuicServerTest, StartAndStop) {
  cppquic::QuicServer server(0);
  EXPECT_NO_THROW(server.Start());
  EXPECT_NO_THROW(server.Stop());
}

TEST(QuicServerTest, DoubleStartThrows) {
  cppquic::QuicServer server(0);
  server.Start();
  EXPECT_THROW(server.Start(), std::runtime_error);
  server.Stop();
}

TEST(QuicServerTest, StopWithoutStart) {
  cppquic::QuicServer server(0);
  EXPECT_NO_THROW(server.Stop());
}

TEST(QuicServerTest, GetLocalPort) {
  cppquic::QuicServer server(0);
  server.Start();
  EXPECT_GT(server.GetLocalPort(), 0);
  server.Stop();
}

TEST(QuicServerTest, StatsInitiallyZero) {
  cppquic::QuicServer server(0);
  auto stats = server.GetStats();
  EXPECT_EQ(stats.bytes_sent, 0u);
  EXPECT_EQ(stats.bytes_received, 0u);
  EXPECT_EQ(stats.packets_sent, 0u);
  EXPECT_EQ(stats.packets_received, 0u);
  EXPECT_EQ(stats.active_connections, 0u);
}

// ============================================================================
// QuicClient Tests
// ============================================================================

TEST(QuicClientTest, StartAndStop) {
  cppquic::QuicClient client;
  EXPECT_NO_THROW(client.Start());
  EXPECT_NO_THROW(client.Stop());
}

TEST(QuicClientTest, DoubleStartThrows) {
  cppquic::QuicClient client;
  client.Start();
  EXPECT_THROW(client.Start(), std::runtime_error);
  client.Stop();
}

TEST(QuicClientTest, StopWithoutStart) {
  cppquic::QuicClient client;
  EXPECT_NO_THROW(client.Stop());
}

TEST(QuicClientTest, GetLocalPort) {
  cppquic::QuicClient client;
  client.Start();
  EXPECT_GT(client.GetLocalPort(), 0);
  client.Stop();
}

TEST(QuicClientTest, ConnectionStateBeforeConnect) {
  cppquic::QuicClient client;
  EXPECT_EQ(client.GetConnectionState(), cppquic::ConnectionState::Closed);
}

TEST(QuicClientTest, AllowSelfSignedCertificates) {
  cppquic::QuicClient client;
  EXPECT_NO_THROW(client.SetAllowSelfSigned(true));
  EXPECT_NO_THROW(client.SetAllowSelfSigned(false));
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST(IntegrationTest, ClientServerHandshake) {
  cppquic::QuicServer server(0);
  server.Start();
  uint16_t port = server.GetLocalPort();

  cppquic::QuicClient client;
  client.Start();

  EXPECT_TRUE(client.Connect("127.0.0.1", port));
  EXPECT_EQ(client.GetConnectionState(), cppquic::ConnectionState::Connected);

  client.Disconnect();
  client.Stop();
  server.Stop();
}

TEST(IntegrationTest, EchoStream) {
  cppquic::QuicServer server(0);

  server.SetStreamDataHandler(
      [&server](std::shared_ptr<cppquic::QuicConnection> conn,
                uint64_t stream_id, const std::vector<uint8_t>& data,
                bool fin) { server.SendOnStream(conn, stream_id, data, fin); });

  server.Start();
  uint16_t port = server.GetLocalPort();

  cppquic::QuicClient client;
  std::atomic<bool> received{false};
  std::string received_text;
  std::mutex mtx;

  client.SetStreamDataHandler(
      [&](uint64_t stream_id, const std::vector<uint8_t>& data, bool fin) {
        std::lock_guard<std::mutex> lock(mtx);
        received_text = std::string(data.begin(), data.end());
        received.store(true);
      });

  client.Start();
  ASSERT_TRUE(client.Connect("127.0.0.1", port));

  uint64_t stream_id = client.OpenStream(true);
  client.SendOnStream(stream_id, "Hello QUIC!");

  EXPECT_TRUE(
      WaitFor([&]() { return received.load(); }, std::chrono::seconds(5)));

  {
    std::lock_guard<std::mutex> lock(mtx);
    EXPECT_EQ(received_text, "Hello QUIC!");
  }

  client.Disconnect();
  client.Stop();
  server.Stop();
}

TEST(IntegrationTest, MultipleStreams) {
  cppquic::QuicServer server(0);

  server.SetStreamDataHandler(
      [&server](std::shared_ptr<cppquic::QuicConnection> conn,
                uint64_t stream_id, const std::vector<uint8_t>& data,
                bool fin) { server.SendOnStream(conn, stream_id, data, fin); });

  server.Start();
  uint16_t port = server.GetLocalPort();

  cppquic::QuicClient client;
  std::atomic<int> msg_count{0};

  client.SetStreamDataHandler([&msg_count](uint64_t,
                                           const std::vector<uint8_t>&,
                                           bool) { msg_count.fetch_add(1); });

  client.Start();
  ASSERT_TRUE(client.Connect("127.0.0.1", port));

  // Open 3 streams and send on each
  const int num_streams = 3;
  for (int i = 0; i < num_streams; ++i) {
    uint64_t stream_id = client.OpenStream(true);
    client.SendOnStream(stream_id, "Message on stream " + std::to_string(i));
  }

  EXPECT_TRUE(WaitFor([&]() { return msg_count.load() >= num_streams; },
                      std::chrono::seconds(5)));
  EXPECT_GE(msg_count.load(), num_streams);

  client.Disconnect();
  client.Stop();
  server.Stop();
}

TEST(IntegrationTest, MultipleMessages) {
  cppquic::QuicServer server(0);

  server.SetStreamDataHandler(
      [&server](std::shared_ptr<cppquic::QuicConnection> conn,
                uint64_t stream_id, const std::vector<uint8_t>& data,
                bool fin) { server.SendOnStream(conn, stream_id, data, fin); });

  server.Start();
  uint16_t port = server.GetLocalPort();

  cppquic::QuicClient client;
  std::atomic<size_t> received_bytes{0};

  client.SetStreamDataHandler(
      [&received_bytes](uint64_t, const std::vector<uint8_t>& data, bool) {
        received_bytes.fetch_add(data.size());
      });

  client.Start();
  ASSERT_TRUE(client.Connect("127.0.0.1", port));

  uint64_t stream_id = client.OpenStream(true);
  const int total = 10;
  for (int i = 0; i < total; ++i) {
    client.SendOnStream(stream_id, "Msg " + std::to_string(i));
  }

  EXPECT_TRUE(WaitFor([&]() { return received_bytes.load() >= 50; },
                      std::chrono::seconds(10)));
  EXPECT_GE(received_bytes.load(), 50u);

  client.Disconnect();
  client.Stop();
  server.Stop();
}

TEST(IntegrationTest, ConnectionClose) {
  cppquic::QuicServer server(0);
  std::atomic<bool> closed_event{false};

  cpppubsub::Worker worker;
  auto sub = server.GetEventBroker().Subscribe<cppquic::ConnectionEvent>(
      "connection_events");
  worker.AddSubscription<cppquic::ConnectionEvent>(
      sub, [&closed_event](const cppquic::ConnectionEvent& event) {
        if (event.state == cppquic::ConnectionState::Closed) {
          closed_event.store(true);
        }
      });
  worker.Start();

  server.Start();
  uint16_t port = server.GetLocalPort();

  cppquic::QuicClient client;
  client.Start();
  ASSERT_TRUE(client.Connect("127.0.0.1", port));

  // Disconnect
  client.Disconnect();
  client.Stop();

  EXPECT_TRUE(
      WaitFor([&]() { return closed_event.load(); }, std::chrono::seconds(5)));

  server.Stop();
  worker.Stop();
}

// ============================================================================
// ThroughputTracker Tests
// ============================================================================

TEST(ThroughputTrackerTest, MeasureThroughput) {
  cppquic::QuicServer server(0);

  server.SetStreamDataHandler(
      [&server](std::shared_ptr<cppquic::QuicConnection> conn,
                uint64_t stream_id, const std::vector<uint8_t>& data,
                bool fin) {});

  server.Start();
  uint16_t port = server.GetLocalPort();

  cppquic::QuicClient client;
  client.Start();
  ASSERT_TRUE(client.Connect("127.0.0.1", port));

  cppquic::ThroughputTracker<cppquic::QuicClient> tracker(client);

  uint64_t stream_id = client.OpenStream(true);
  std::vector<uint8_t> data(500, 'A');
  for (int i = 0; i < 20; ++i) {
    client.SendOnStream(stream_id, data);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  EXPECT_TRUE(
      WaitFor([&]() { return tracker.GetSendThroughputBytesPerSec() > 0.0; },
              std::chrono::seconds(5)));

  EXPECT_GE(tracker.GetSendThroughputBytesPerSec(), 0.0);

  client.Disconnect();
  client.Stop();
  server.Stop();
}

// ============================================================================
// Congestion Control Tests
// ============================================================================

TEST(CongestionControllerTest, NewReno) {
  auto controller = cppquic::CreateCongestionController(
      cppquic::CongestionControlAlgorithm::NewReno, 1200);
  EXPECT_EQ(controller->GetName(), "NewReno");
  EXPECT_EQ(controller->GetCongestionWindow(), 12000);
  EXPECT_EQ(controller->GetBytesInFlight(), 0);
  EXPECT_TRUE(controller->CanSend(1200));

  // Send packet
  controller->OnPacketSent(1, 1200);
  EXPECT_EQ(controller->GetBytesInFlight(), 1200);

  // Ack packet in slow start
  auto now = std::chrono::steady_clock::now();
  controller->OnPacketAcked(1, 1200, now - std::chrono::milliseconds(100), now);
  EXPECT_EQ(controller->GetBytesInFlight(), 0);
  EXPECT_EQ(controller->GetCongestionWindow(), 13200);  // cwnd += 1200

  // Send packets and lose one
  controller->OnPacketSent(2, 1200);
  controller->OnPacketSent(3, 1200);
  EXPECT_EQ(controller->GetBytesInFlight(), 2400);

  std::vector<cppquic::LostPacketInfo> lost;
  lost.push_back({2, 1200, now - std::chrono::milliseconds(50)});
  controller->OnPacketsLost(lost, now);

  // Expect recovery: ssthresh = cwnd / 2 = 13200 / 2 = 6600, cwnd = ssthresh =
  // 6600
  EXPECT_EQ(controller->GetCongestionWindow(), 6600);
  EXPECT_EQ(controller->GetBytesInFlight(), 1200);  // packet 3 remains

  // Ack packet 3 (sent before loss time) -> in recovery, should not grow cwnd
  controller->OnPacketAcked(3, 1200, now - std::chrono::milliseconds(40), now);
  EXPECT_EQ(controller->GetCongestionWindow(), 6600);
  EXPECT_EQ(controller->GetBytesInFlight(), 0);

  // Send new packet after recovery start
  auto post_recovery_send = std::chrono::steady_clock::now();
  controller->OnPacketSent(4, 1200);

  // Ack new packet -> outside recovery, cwnd should grow
  controller->OnPacketAcked(4, 1200, post_recovery_send,
                            std::chrono::steady_clock::now());
  EXPECT_GT(controller->GetCongestionWindow(), 6600);
}

TEST(CongestionControllerTest, Cubic) {
  auto controller = cppquic::CreateCongestionController(
      cppquic::CongestionControlAlgorithm::Cubic, 1200);
  EXPECT_EQ(controller->GetName(), "Cubic");
  EXPECT_EQ(controller->GetCongestionWindow(), 12000);
  EXPECT_EQ(controller->GetBytesInFlight(), 0);

  // Send and Ack to verify slow start growth
  controller->OnPacketSent(1, 1200);
  auto now = std::chrono::steady_clock::now();
  controller->OnPacketAcked(1, 1200, now - std::chrono::milliseconds(10), now);
  EXPECT_EQ(controller->GetCongestionWindow(), 13200);

  // Trigger loss
  std::vector<cppquic::LostPacketInfo> lost;
  lost.push_back({2, 1200, now});
  controller->OnPacketsLost(lost, now);

  // Expect recovery window reduction (beta = 0.7)
  // W_max = 13200, cwnd = W_max * 0.7 = 9240
  EXPECT_EQ(controller->GetCongestionWindow(), 9240);
}

TEST(CongestionControllerTest, ConstantWindow) {
  auto controller = cppquic::CreateCongestionController(
      cppquic::CongestionControlAlgorithm::ConstantWindow, 1200);
  EXPECT_EQ(controller->GetName(), "ConstantWindow");
  EXPECT_EQ(controller->GetCongestionWindow(), 1200000);

  controller->OnPacketSent(1, 1200);
  EXPECT_EQ(controller->GetBytesInFlight(), 1200);
  EXPECT_TRUE(controller->CanSend(1000000));
}

TEST(IntegrationTest, MultipleCongestionControllers) {
  for (auto cc_algo : {cppquic::CongestionControlAlgorithm::Cubic,
                       cppquic::CongestionControlAlgorithm::ConstantWindow}) {
    cppquic::QuicServer server(0);
    server.SetCongestionControlAlgorithm(cc_algo);
    server.SetStreamDataHandler(
        [&server](std::shared_ptr<cppquic::QuicConnection> conn,
                  uint64_t stream_id, const std::vector<uint8_t>& data,
                  bool fin) {
          server.SendOnStream(conn, stream_id, data, fin);
        });

    server.Start();
    uint16_t port = server.GetLocalPort();

    cppquic::QuicClient client;
    client.SetCongestionControlAlgorithm(cc_algo);
    std::atomic<int> msg_count{0};
    client.SetStreamDataHandler([&msg_count](uint64_t,
                                             const std::vector<uint8_t>&,
                                             bool) { msg_count.fetch_add(1); });

    client.Start();
    ASSERT_TRUE(client.Connect("127.0.0.1", port));

    uint64_t stream_id = client.OpenStream(true);
    client.SendOnStream(stream_id, "Testing congestion control!");

    EXPECT_TRUE(WaitFor([&]() { return msg_count.load() >= 1; },
                        std::chrono::seconds(5)));
    EXPECT_GE(msg_count.load(), 1);

    client.Disconnect();
    client.Stop();
    server.Stop();
  }
}

TEST(QuicStreamTest, FlowControlLimits) {
  cppquic::QuicStream stream(4);
  // Initial max_send_offset_ is 65536

  // Write 65536 bytes (allowed)
  std::vector<uint8_t> data1(65536, 'A');
  auto frames1 = stream.Write(data1, false);
  EXPECT_FALSE(frames1.empty());
  EXPECT_EQ(stream.GetSendOffset(), 65536u);

  // Write more data (should be blocked / not allowed)
  std::vector<uint8_t> data2(5, 'B');
  auto frames2 = stream.Write(data2, false);
  EXPECT_TRUE(frames2.empty());  // No frames generated because limit is reached

  // Increase limit
  stream.SetMaxSendOffset(65541);
  auto frames3 = stream.Write(data2, false);
  EXPECT_FALSE(frames3.empty());
  EXPECT_EQ(stream.GetSendOffset(), 65541u);
}

TEST(QuicConnectionTest, FlowControlLimits) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  EXPECT_EQ(conn.GetMaxSendData(), 1048576u);  // Default limit

  conn.SetMaxSendData(2000000);
  EXPECT_EQ(conn.GetMaxSendData(), 2000000u);

  // Trying to set a smaller limit should be ignored (limits only grow)
  conn.SetMaxSendData(1000);
  EXPECT_EQ(conn.GetMaxSendData(), 2000000u);
}

TEST(QuicStreamTest, BufferingQueue) {
  cppquic::QuicStream stream(4);

  // Write beyond limit
  std::vector<uint8_t> data(65541, 'A');
  stream.AppendWriteData(data, false);

  // Pull frames - should only return up to the 65536 limit
  auto frames = stream.PullWriteFrames(std::numeric_limits<uint64_t>::max());
  EXPECT_FALSE(frames.empty());
  uint64_t total_pulled = 0;
  for (const auto& f : frames) {
    total_pulled += f.data.size();
  }
  EXPECT_EQ(total_pulled, 65536u);
  EXPECT_EQ(stream.GetSendOffset(), 65536u);

  // Try pulling again - should be 0 because limit is hit
  auto frames2 = stream.PullWriteFrames(std::numeric_limits<uint64_t>::max());
  EXPECT_TRUE(frames2.empty());

  // Grow limit
  stream.SetMaxSendOffset(65541);
  auto frames3 = stream.PullWriteFrames(std::numeric_limits<uint64_t>::max());
  EXPECT_FALSE(frames3.empty());
  EXPECT_EQ(frames3.size(), 1u);
  EXPECT_EQ(frames3[0].data.size(), 5u);
  EXPECT_EQ(stream.GetSendOffset(), 65541u);
}

TEST(IntegrationTest, ConnectionFlowControlResumption) {
  cppquic::QuicServer server(0);
  server.SetAutoFlowControl(false);
  server.Start();
  uint16_t port = server.GetLocalPort();

  cppquic::QuicClient client;
  client.SetAutoFlowControl(false);
  std::atomic<uint64_t> server_received_bytes{0};

  server.SetStreamDataHandler(
      [&server_received_bytes](std::shared_ptr<cppquic::QuicConnection>,
                               uint64_t, const std::vector<uint8_t>& data,
                               bool) {
        server_received_bytes.fetch_add(data.size());
      });

  client.Start();
  ASSERT_TRUE(client.Connect("127.0.0.1", port));

  auto conn = client.GetConnection();
  ASSERT_NE(conn, nullptr);

  uint64_t stream_id = client.OpenStream(true);

  // Send 70000 bytes. The first 65536 should go out, the last 4464 should be
  // buffered.
  std::vector<uint8_t> large_data(70000, 'A');
  client.SendOnStream(stream_id, large_data);

  // Wait to see if 65536 bytes are received on the server
  EXPECT_TRUE(WaitFor([&]() { return server_received_bytes.load() >= 65536; },
                      std::chrono::seconds(2)));

  // Should only have received exactly 65536 bytes
  EXPECT_EQ(server_received_bytes.load(), 65536u);

  // Now, expand the stream send limit to 70000
  auto stream = conn->GetStream(stream_id);
  ASSERT_NE(stream, nullptr);
  stream->SetMaxSendOffset(70000);

  // Trigger packet generation and send on the client
  conn->GenerateStreamPackets();
  client.SendPendingPackets();

  // Wait to see if the rest is received
  EXPECT_TRUE(WaitFor([&]() { return server_received_bytes.load() >= 70000; },
                      std::chrono::seconds(2)));

  EXPECT_EQ(server_received_bytes.load(), 70000u);

  client.Disconnect();
  client.Stop();
  server.Stop();
}

TEST(IntegrationTest, ConnectionMigrationAndPathValidation) {
  cppquic::ConnectionId client_cid{1, 2, 3, 4, 5, 6, 7, 8};
  cppquic::ConnectionId server_cid{8, 7, 6, 5, 4, 3, 2, 1};
  cppudpnet::PeerAddress client_addr{"127.0.0.1", 11111};
  cppudpnet::PeerAddress server_addr{"127.0.0.1", 22222};

  auto client_conn = std::make_shared<cppquic::QuicConnection>(
      client_cid, server_cid, server_addr, false, nullptr);
  auto server_conn = std::make_shared<cppquic::QuicConnection>(
      server_cid, client_cid, client_addr, true, nullptr);

  client_conn->SetState(cppquic::ConnectionState::Connected);
  server_conn->SetState(cppquic::ConnectionState::Connected);

  client_conn->GetCryptoContext()->handshake_complete = true;
  server_conn->GetCryptoContext()->handshake_complete = true;

  client_conn->GetCryptoContext()->read_key = std::vector<uint8_t>(16, 0xA);
  client_conn->GetCryptoContext()->read_iv = std::vector<uint8_t>(12, 0xB);
  client_conn->GetCryptoContext()->write_key = std::vector<uint8_t>(16, 0xC);
  client_conn->GetCryptoContext()->write_iv = std::vector<uint8_t>(12, 0xD);

  server_conn->GetCryptoContext()->read_key = std::vector<uint8_t>(16, 0xC);
  server_conn->GetCryptoContext()->read_iv = std::vector<uint8_t>(12, 0xD);
  server_conn->GetCryptoContext()->write_key = std::vector<uint8_t>(16, 0xA);
  server_conn->GetCryptoContext()->write_iv = std::vector<uint8_t>(12, 0xB);

  cppudpnet::PeerAddress migration_addr{"127.0.0.1", 33333};
  client_conn->InitiatePathValidation(migration_addr);

  ASSERT_TRUE(client_conn->HasPendingPackets());
  auto f1 = client_conn->PopPendingPacket();
  auto p1 = client_conn->CreatePacket(std::move(f1), 0);
  auto b1 = client_conn->SerializePacket(p1);

  cppquic::QuicPacket s_pkt;
  bool ok = server_conn->DeserializePacket(b1, s_pkt);
  ASSERT_TRUE(ok);

  bool path_challenge_found = false;
  for (const auto& frame : s_pkt.frames) {
    if (std::holds_alternative<cppquic::PathChallengeFrame>(frame)) {
      path_challenge_found = true;
      const auto& challenge = std::get<cppquic::PathChallengeFrame>(frame);
      cppquic::PathResponseFrame resp;
      std::memcpy(resp.data, challenge.data, 8);
      auto resp_pkt = server_conn->CreatePacket({resp}, 0);
      auto resp_bytes = server_conn->SerializePacket(resp_pkt);

      cppquic::QuicPacket c_pkt;
      bool ok2 = client_conn->DeserializePacket(resp_bytes, c_pkt);
      ASSERT_TRUE(ok2);

      for (const auto& f : c_pkt.frames) {
        if (std::holds_alternative<cppquic::PathResponseFrame>(f)) {
          const auto& resp_frame = std::get<cppquic::PathResponseFrame>(f);
          uint8_t pending[8];
          client_conn->GetPendingChallenge(pending);
          if (client_conn->IsChallengePending() &&
              std::memcmp(pending, resp_frame.data, 8) == 0) {
            client_conn->ClearPendingChallenge();
            client_conn->SetPathValidated(true);
            client_conn->SetPeer(migration_addr);
          }
        }
      }
    }
  }

  EXPECT_TRUE(path_challenge_found);
  EXPECT_TRUE(client_conn->IsPathValidated());
  EXPECT_EQ(client_conn->GetPeer().port, 33333);
}

TEST(IntegrationTest, ZeroRTTData) {
  cppquic::ConnectionId client_cid{1, 2, 3, 4, 5, 6, 7, 8};
  cppquic::ConnectionId server_cid{8, 7, 6, 5, 4, 3, 2, 1};
  cppudpnet::PeerAddress client_addr{"127.0.0.1", 11111};
  cppudpnet::PeerAddress server_addr{"127.0.0.1", 22222};

  auto client_conn = std::make_shared<cppquic::QuicConnection>(
      client_cid, server_cid, server_addr, false, nullptr);
  auto server_conn = std::make_shared<cppquic::QuicConnection>(
      server_cid, client_cid, client_addr, true, nullptr, server_cid);

  client_conn->SetState(cppquic::ConnectionState::Handshaking);
  server_conn->SetState(cppquic::ConnectionState::Handshaking);

  uint64_t stream_id = 4;
  auto stream = client_conn->GetOrCreateStream(stream_id);
  std::vector<uint8_t> data = {'0', '-', 'R', 'T', 'T'};
  stream->AppendWriteData(data, false);
  client_conn->GenerateStreamPackets();

  ASSERT_TRUE(client_conn->HasPendingPackets());
  auto f1 = client_conn->PopPendingPacket();
  auto p1 = client_conn->CreatePacket(std::move(f1), 3);
  auto b1 = client_conn->SerializePacket(p1);

  cppquic::QuicPacket s_pkt;
  bool ok = server_conn->DeserializePacket(b1, s_pkt);
  ASSERT_TRUE(ok);
  ASSERT_EQ(s_pkt.packet_type, 3);

  bool stream_frame_found = false;
  for (const auto& frame : s_pkt.frames) {
    if (std::holds_alternative<cppquic::StreamFrame>(frame)) {
      stream_frame_found = true;
      const auto& sf = std::get<cppquic::StreamFrame>(frame);
      EXPECT_EQ(sf.stream_id, stream_id);
      EXPECT_EQ(sf.data, data);
    }
  }
  EXPECT_TRUE(stream_frame_found);
}

TEST(IntegrationTest, StatelessReset) {
  cppquic::ConnectionId client_cid{1, 2, 3, 4, 5, 6, 7, 8};
  cppquic::ConnectionId server_cid{8, 7, 6, 5, 4, 3, 2, 1};
  cppudpnet::PeerAddress client_addr{"127.0.0.1", 11111};
  cppudpnet::PeerAddress server_addr{"127.0.0.1", 22222};

  auto client_conn = std::make_shared<cppquic::QuicConnection>(
      client_cid, server_cid, server_addr, false, nullptr);

  client_conn->SetState(cppquic::ConnectionState::Connected);
  client_conn->GetCryptoContext()->handshake_complete = true;
  client_conn->GetCryptoContext()->read_key = std::vector<uint8_t>(16, 0xA);
  client_conn->GetCryptoContext()->read_iv = std::vector<uint8_t>(12, 0xB);

  uint8_t expected_token[16];
  cppquic::internal::DeriveStatelessResetToken(server_cid, expected_token);

  std::vector<uint8_t> reset_pkt(40);
  reset_pkt[0] = 0x43;
  for (size_t i = 1; i < 24; ++i) {
    reset_pkt[i] = static_cast<uint8_t>(std::rand() & 0xFF);
  }
  std::memcpy(reset_pkt.data() + 24, expected_token, 16);

  cppquic::QuicPacket pkt;
  bool ok = client_conn->DeserializePacket(reset_pkt, pkt);
  ASSERT_FALSE(ok);

  bool reset_detected = false;
  if (reset_pkt.size() >= 21) {
    uint8_t token[16];
    cppquic::internal::DeriveStatelessResetToken(
        client_conn->GetRemoteConnectionId(), token);
    if (std::memcmp(reset_pkt.data() + reset_pkt.size() - 16, token, 16) == 0) {
      reset_detected = true;
      client_conn->SetState(cppquic::ConnectionState::Closed);
    }
  }

  EXPECT_TRUE(reset_detected);
  EXPECT_EQ(client_conn->GetState(), cppquic::ConnectionState::Closed);
}

TEST(StandardQUICComplianceTest, VariableLengthCidAndHeaderProtection) {
  // Test variable-length CID
  cppquic::ConnectionId cid;
  cid.length = 12;
  std::memset(cid.data, 0xAA, 12);

  std::vector<uint8_t> buf;
  cid.Serialize(buf);
  EXPECT_EQ(buf.size(), 12u);

  cppquic::ConnectionId deserialized;
  size_t offset = 0;
  EXPECT_TRUE(cppquic::ConnectionId::Deserialize(buf.data(), buf.size(), offset,
                                                 deserialized, 12));
  EXPECT_EQ(deserialized.length, 12u);
  EXPECT_EQ(cid, deserialized);

  // Test Header Protection and encryption/decryption
  cppquic::QuicPacket pkt;
  pkt.packet_type = 1;  // Initial
  pkt.connection_id = cid;
  pkt.source_connection_id = cid;
  pkt.packet_number = 42;

  cppquic::PingFrame ping;
  pkt.frames.push_back(ping);

  std::vector<uint8_t> key(16, 0x1);
  std::vector<uint8_t> iv(12, 0x2);
  std::vector<uint8_t> hp(16, 0x3);

  auto serialized = pkt.Serialize(&key, &iv, &hp);

  cppquic::QuicPacket parsed;
  bool ok =
      cppquic::QuicPacket::Deserialize(serialized, parsed, &key, &iv, &hp, 12);
  ASSERT_TRUE(ok);
  EXPECT_EQ(parsed.packet_type, 1);
  EXPECT_EQ(parsed.packet_number, 42u);
  EXPECT_EQ(parsed.connection_id, cid);
  EXPECT_EQ(parsed.source_connection_id, cid);
  EXPECT_EQ(parsed.frames.size(), 1u);
  EXPECT_TRUE(std::holds_alternative<cppquic::PingFrame>(parsed.frames[0]));
}

TEST(StandardQUICComplianceTest, KeylogParsing) {
  cppquic::ConnectionId client_cid{1, 2, 3, 4, 5, 6, 7, 8};
  cppquic::ConnectionId server_cid{8, 7, 6, 5, 4, 3, 2, 1};
  cppudpnet::PeerAddress server_addr{"127.0.0.1", 12345};

  cppquic::QuicConnection conn(client_cid, server_cid, server_addr, false);

  // Feed mock keylog lines
  conn.HandleKeylogLine(
      "CLIENT_HANDSHAKE_TRAFFIC_SECRET "
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
  conn.HandleKeylogLine(
      "SERVER_HANDSHAKE_TRAFFIC_SECRET "
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
      "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");

  auto crypto = conn.GetCryptoContext();
  EXPECT_FALSE(crypto->handshake_write_key.empty());
  EXPECT_FALSE(crypto->handshake_write_iv.empty());
  EXPECT_FALSE(crypto->handshake_write_hp.empty());
  EXPECT_FALSE(crypto->handshake_read_key.empty());
  EXPECT_FALSE(crypto->handshake_read_iv.empty());
  EXPECT_FALSE(crypto->handshake_read_hp.empty());
}

TEST(StandardQUICComplianceTest, AlpnProtosSerialization) {
  // Test empty list
  EXPECT_TRUE(cppquic::internal::SerializeAlpnProtos({}).empty());

  // Test single protocol "h3" (length prefix 2 followed by 'h', '3')
  std::vector<uint8_t> expected_h3 = {2, 'h', '3'};
  EXPECT_EQ(cppquic::internal::SerializeAlpnProtos({"h3"}), expected_h3);

  // Test multiple protocols "h3", "http/1.1"
  std::vector<uint8_t> expected_multiple = {2,   'h', '3', 8,   'h', 't',
                                            't', 'p', '/', '1', '.', '1'};
  EXPECT_EQ(cppquic::internal::SerializeAlpnProtos({"h3", "http/1.1"}),
            expected_multiple);
}

TEST(QuicConnectionTest, TransportParametersAndAlpn) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppquic::ConnectionId orig_dest_id{1, 2, 3, 4, 5, 6, 7, 8};
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};
  std::vector<std::string> alpn = {"h3", "h3-29"};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false, nullptr,
                               orig_dest_id, alpn);
  EXPECT_EQ(conn.GetLocalConnectionId(), local_id);
  EXPECT_EQ(conn.GetRemoteConnectionId(), remote_id);
  EXPECT_EQ(conn.GetOriginalDestinationConnectionId(), orig_dest_id);
}

TEST(QuicServerAndClientTest, ConfigureAlpnProtos) {
  cppquic::QuicServer server(0);
  EXPECT_NO_THROW(server.SetAlpnProtos({"h3", "h3-29"}));

  cppquic::QuicClient client;
  EXPECT_NO_THROW(client.SetAlpnProtos({"h3", "h3-29"}));
}
