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

TEST(QuicPacketTest, SerializeDeserializeHandshake) {
  cppquic::QuicPacket pkt;
  pkt.connection_id = cppquic::internal::GenerateConnectionId();
  pkt.packet_number = 0;

  cppquic::HandshakeFrame hs;
  hs.type = cppquic::HandshakeFrame::Type::ClientHello;
  hs.source_connection_id = cppquic::internal::GenerateConnectionId();
  hs.destination_connection_id = cppquic::ConnectionId{};
  pkt.frames.push_back(hs);

  auto bytes = pkt.Serialize();

  cppquic::QuicPacket decoded;
  EXPECT_TRUE(cppquic::QuicPacket::Deserialize(bytes, decoded));

  auto& frame = std::get<cppquic::HandshakeFrame>(decoded.frames[0]);
  EXPECT_EQ(frame.type, cppquic::HandshakeFrame::Type::ClientHello);
  EXPECT_EQ(frame.source_connection_id, hs.source_connection_id);
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

  conn.RecordReceivedPacket(5);
  conn.RecordReceivedPacket(6);
  conn.RecordReceivedPacket(7);

  auto ack = conn.GenerateAck();
  EXPECT_EQ(ack.largest_acknowledged, 7u);
  EXPECT_EQ(ack.acknowledged_packets.size(), 3u);

  // Second call should return empty (already consumed)
  auto ack2 = conn.GenerateAck();
  EXPECT_TRUE(ack2.acknowledged_packets.empty());
}

TEST(QuicConnectionTest, HandshakePacket) {
  auto local_id = cppquic::internal::GenerateConnectionId();
  auto remote_id = cppquic::internal::GenerateConnectionId();
  cppudpnet::PeerAddress peer{"127.0.0.1", 4433};

  cppquic::QuicConnection conn(local_id, remote_id, peer, false);
  auto pkt = conn.CreateHandshakePacket();

  EXPECT_EQ(pkt.frames.size(), 1u);
  auto& hs = std::get<cppquic::HandshakeFrame>(pkt.frames[0]);
  EXPECT_EQ(hs.type, cppquic::HandshakeFrame::Type::ClientHello);
  EXPECT_EQ(hs.source_connection_id, local_id);
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
  std::atomic<int> msg_count{0};

  client.SetStreamDataHandler([&msg_count](uint64_t,
                                           const std::vector<uint8_t>&,
                                           bool) { msg_count.fetch_add(1); });

  client.Start();
  ASSERT_TRUE(client.Connect("127.0.0.1", port));

  uint64_t stream_id = client.OpenStream(true);
  const int total = 10;
  for (int i = 0; i < total; ++i) {
    client.SendOnStream(stream_id, "Msg " + std::to_string(i));
  }

  EXPECT_TRUE(WaitFor([&]() { return msg_count.load() >= total; },
                      std::chrono::seconds(10)));
  EXPECT_GE(msg_count.load(), total);

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

