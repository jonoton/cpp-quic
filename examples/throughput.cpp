#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "cppquic.hpp"

using namespace cppquic;

std::atomic<uint64_t> server_bytes_received(0);
std::atomic<uint64_t> client_bytes_received(0);

const size_t PACKET_SIZE = 1200;
const size_t TOTAL_PACKETS = 10000;
const uint64_t TOTAL_BYTES = TOTAL_PACKETS * PACKET_SIZE;
const int PACING_DELAY_US = 10;

void RunServer() {
  QuicServer server(4435);
  server.SetRecvBufferSize(8 * 1024 * 1024);
  server.SetSendBufferSize(8 * 1024 * 1024);
  server.SetIdleTimeout(std::chrono::milliseconds(5000));

  server.SetStreamDataHandler(
      [&server](std::shared_ptr<QuicConnection> conn, uint64_t stream_id,
                const std::vector<uint8_t> &data, bool fin) {
        server_bytes_received += data.size();
        // Echo back
        server.SendOnStream(conn, stream_id, data, fin);
      });

  server.SetErrorHandler([](int code, const std::string &msg) {
    std::cerr << "[Server Error] " << msg << " (Code: " << code << ")"
              << std::endl;
  });

  try {
    server.Start();
    std::cout << "[Server] Listening on port 4435..." << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "[Server] Start failed: " << e.what() << std::endl;
    return;
  }

  auto server_start = std::chrono::steady_clock::now();
  uint64_t last_received = 0;
  auto last_recv_time = std::chrono::steady_clock::now();

  while (server_bytes_received < TOTAL_BYTES) {
    auto now = std::chrono::steady_clock::now();
    if (now - server_start > std::chrono::seconds(30)) {
      std::cerr << "[Server] Wait timeout reached." << std::endl;
      break;
    }
    if (server_bytes_received > 0 && server_bytes_received == last_received) {
      if (now - last_recv_time > std::chrono::seconds(5)) {
        std::cout << "[Server] No data for 5 seconds. Stopping wait."
                  << std::endl;
        break;
      }
    } else if (server_bytes_received > last_received) {
      last_received = server_bytes_received;
      last_recv_time = now;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  server.Stop();
  std::cout << "[Server] Stopped." << std::endl;
}

void RunClient() {
  QuicClient client;
  client.SetRecvBufferSize(8 * 1024 * 1024);
  client.SetSendBufferSize(8 * 1024 * 1024);

  client.SetStreamDataHandler(
      [](uint64_t stream_id, const std::vector<uint8_t> &data, bool fin) {
        client_bytes_received += data.size();
      });

  client.SetErrorHandler([](int code, const std::string &msg) {
    std::cerr << "[Client Error] " << msg << " (Code: " << code << ")"
              << std::endl;
  });

  try {
    client.Start();
    std::cout << "[Client] Bound to port " << client.GetLocalPort()
              << std::endl;

    if (!client.Connect("127.0.0.1", 4435)) {
      std::cerr << "[Client] Failed to connect." << std::endl;
      client.Stop();
      return;
    }
    std::cout << "[Client] Connected!" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "[Client] Start failed: " << e.what() << std::endl;
    return;
  }

  uint64_t stream_id = client.OpenStream(true);
  std::vector<uint8_t> payload(PACKET_SIZE, 'A');

  ThroughputTracker<QuicClient> tracker(client);

  auto transfer_start = std::chrono::steady_clock::now();
  double peak_send = 0.0;
  double peak_recv = 0.0;

  std::cout << "[Client] Sending " << TOTAL_PACKETS << " packets of "
            << PACKET_SIZE << " bytes (" << (TOTAL_BYTES / (1024 * 1024))
            << " MB)..." << std::endl;

  for (size_t i = 0; i < TOTAL_PACKETS; ++i) {
    bool is_last = (i == TOTAL_PACKETS - 1);
    client.SendOnStream(stream_id, payload, is_last);

    double current_send = tracker.GetSendThroughputBytesPerSec();
    double current_recv = tracker.GetRecvThroughputBytesPerSec();
    if (current_send > peak_send) peak_send = current_send;
    if (current_recv > peak_recv) peak_recv = current_recv;

    if (PACING_DELAY_US > 0) {
      auto start = std::chrono::steady_clock::now();
      while (std::chrono::duration_cast<std::chrono::microseconds>(
                 std::chrono::steady_clock::now() - start)
                 .count() < PACING_DELAY_US) {
        // Spin-wait for pacing
      }
    }
  }

  std::cout << "[Client] All packets sent. Waiting for echoes..." << std::endl;

  auto wait_start = std::chrono::steady_clock::now();
  uint64_t last_client_received = 0;
  auto last_client_recv_time = std::chrono::steady_clock::now();

  while (client_bytes_received < TOTAL_BYTES) {
    auto now = std::chrono::steady_clock::now();
    if (now - wait_start > std::chrono::seconds(15)) {
      std::cerr << "[Client] Timed out waiting for echoes!" << std::endl;
      break;
    }
    if (client_bytes_received > 0 &&
        client_bytes_received == last_client_received) {
      if (now - last_client_recv_time > std::chrono::seconds(5)) {
        std::cout << "[Client] No echoes for 5 seconds. Stopping wait."
                  << std::endl;
        break;
      }
    } else if (client_bytes_received > last_client_received) {
      last_client_received = client_bytes_received;
      last_client_recv_time = now;
    }

    double current_send = tracker.GetSendThroughputBytesPerSec();
    double current_recv = tracker.GetRecvThroughputBytesPerSec();
    if (current_send > peak_send) peak_send = current_send;
    if (current_recv > peak_recv) peak_recv = current_recv;

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto transfer_end = std::chrono::steady_clock::now();
  std::chrono::duration<double> duration = transfer_end - transfer_start;
  double elapsed = duration.count();

  auto stats = client.GetStats();

  client.Disconnect();
  client.Stop();
  std::cout << "[Client] Stopped." << std::endl;

  double avg_send = elapsed > 0 ? (stats.bytes_sent / elapsed) : 0.0;
  double avg_recv =
      elapsed > 0 ? (client_bytes_received.load() / elapsed) : 0.0;

  auto format_bytes = [](uint64_t bytes) {
    auto scaled = ScaleBytes(bytes);
    char buf[128];
    snprintf(buf, sizeof(buf), "%.2f %s", scaled.value, scaled.unit);
    return std::string(buf);
  };

  auto format_tp = [](double bytes_per_sec) {
    auto scaled_bytes = ScaleBytes(static_cast<uint64_t>(bytes_per_sec));
    auto scaled_bits = ScaleBits(bytes_per_sec * 8.0);
    char buf[128];
    snprintf(buf, sizeof(buf), "%.2f %s/s (%.2f %s)", scaled_bytes.value,
             scaled_bytes.unit, scaled_bits.value, scaled_bits.unit);
    return std::string(buf);
  };

  std::cout << "\n========================================" << std::endl;
  std::cout << "     QUIC CLIENT THROUGHPUT METRICS     " << std::endl;
  std::cout << "========================================" << std::endl;
  std::cout << "Transfer Duration: " << elapsed << " seconds" << std::endl;
  std::cout << "Total Packets Sent: " << stats.packets_sent << std::endl;
  std::cout << "Total Packets Received: " << stats.packets_received
            << std::endl;
  std::cout << "Total Bytes Sent: " << stats.bytes_sent << " ("
            << format_bytes(stats.bytes_sent) << ")" << std::endl;
  std::cout << "Total Bytes Received (Echo): " << client_bytes_received.load()
            << " (" << format_bytes(client_bytes_received.load()) << ")"
            << std::endl;
  std::cout << "Retransmissions: " << stats.retransmissions << std::endl;
  std::cout << "Avg Send Throughput: " << format_tp(avg_send) << std::endl;
  std::cout << "Avg Recv Throughput: " << format_tp(avg_recv) << std::endl;
  std::cout << "Peak Send Throughput: " << format_tp(peak_send) << std::endl;
  std::cout << "Peak Recv Throughput: " << format_tp(peak_recv) << std::endl;
  std::cout << "========================================\n" << std::endl;
}

int main() {
  SetLogger(
      [](LogSeverity severity, const std::string &cls, const std::string &msg) {
        std::cout << "[" << cls << "] " << msg << std::endl;
      });

  std::thread server_thread(RunServer);
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  std::thread client_thread(RunClient);

  client_thread.join();
  server_thread.join();

  auto scaled_srv = ScaleBytes(server_bytes_received.load());
  auto scaled_cli = ScaleBytes(client_bytes_received.load());
  char buf_srv[128], buf_cli[128];
  snprintf(buf_srv, sizeof(buf_srv), "%.2f %s", scaled_srv.value,
           scaled_srv.unit);
  snprintf(buf_cli, sizeof(buf_cli), "%.2f %s", scaled_cli.value,
           scaled_cli.unit);

  std::cout << "Test completed." << std::endl;
  std::cout << "Total bytes received by Server: "
            << server_bytes_received.load() << " (" << buf_srv << ")"
            << std::endl;
  std::cout << "Total bytes received by Client: "
            << client_bytes_received.load() << " (" << buf_cli << ")"
            << std::endl;
  return 0;
}
