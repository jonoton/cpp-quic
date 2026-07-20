#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "cppquic.hpp"

using namespace cppquic;

std::atomic<uint64_t> server_bytes_received(0);
std::atomic<uint64_t> client_bytes_received(0);
bool use_backpressure = false;

std::mutex server_mutex;
std::condition_variable server_startup_cv;
bool server_listening = false;
std::condition_variable server_connection_cv;
bool client_connected = false;
std::condition_variable server_data_cv;
uint16_t server_port = 0;  // populated after Start()

std::mutex client_mutex;
std::condition_variable client_data_cv;
std::condition_variable flow_control_cv;

const size_t PACKET_SIZE = 1200;
const size_t TOTAL_PACKETS = 10000;
const uint64_t TOTAL_BYTES = TOTAL_PACKETS * PACKET_SIZE;

void RunServer() {
  QuicServer server(0);
  server.SetRecvBufferSize(16 * 1024 * 1024);
  server.SetSendBufferSize(16 * 1024 * 1024);
  server.SetIdleTimeout(std::chrono::milliseconds(120000));
  server.SetCongestionControlAlgorithm(CongestionControlAlgorithm::NewReno);

  server.SetConnectionHandler([](std::shared_ptr<QuicConnection>) {
    std::lock_guard<std::mutex> lock(server_mutex);
    client_connected = true;
    server_connection_cv.notify_one();
  });

  server.SetStreamDataHandler(
      [&server](std::shared_ptr<QuicConnection> conn, uint64_t stream_id,
                const std::vector<uint8_t> &data, bool fin) {
        server_bytes_received += data.size();
        server.SendOnStream(conn, stream_id, data, fin);
        server_data_cv.notify_one();
      });

  server.SetErrorHandler([](int code, const std::string &msg) {
    std::cerr << "[Server Error] " << msg << " (Code: " << code << ")"
              << std::endl;
  });

  try {
    server.Start();
    {
      std::lock_guard<std::mutex> lock(server_mutex);
      server_port = server.GetLocalPort();
      server_listening = true;
    }
    server_startup_cv.notify_one();
    std::cout << "[Server] Listening on port " << server_port << "..."
              << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "[Server] Start failed: " << e.what() << std::endl;
    return;
  }

  // Wait for client to connect
  {
    std::unique_lock<std::mutex> lock(server_mutex);
    if (!server_connection_cv.wait_for(lock, std::chrono::seconds(10),
                                       [] { return client_connected; })) {
      std::cerr << "[Server] Timeout waiting for client to connect."
                << std::endl;
    }
  }

  // Wait until all intended bytes are received. Activity timeout is handled via
  // wait_for.
  {
    std::unique_lock<std::mutex> lock(server_mutex);
    while (server_bytes_received.load() < TOTAL_BYTES) {
      if (server_data_cv.wait_for(lock, std::chrono::seconds(30)) ==
          std::cv_status::timeout) {
        std::cout << "[Server] Stalled — no new data for 30 s. Stopping."
                  << std::endl;
        break;
      }
    }
  }

  if (server_bytes_received.load() >= TOTAL_BYTES) {
    std::cout << "[Server] All " << TOTAL_BYTES
              << " bytes received. Waiting for client to disconnect..."
              << std::endl;
    auto wait_disconnect_start = std::chrono::steady_clock::now();
    while (server.GetActiveConnectionCount() > 0) {
      if (std::chrono::steady_clock::now() - wait_disconnect_start >
          std::chrono::seconds(10)) {
        std::cout << "[Server] Timeout waiting for client to disconnect."
                  << std::endl;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  server.Stop();
  std::cout << "[Server] Stopped." << std::endl;
}

void RunClient() {
  QuicClient client;
  client.SetRecvBufferSize(16 * 1024 * 1024);
  client.SetSendBufferSize(16 * 1024 * 1024);
  client.SetCongestionControlAlgorithm(CongestionControlAlgorithm::NewReno);

  client.SetStreamDataHandler(
      [](uint64_t, const std::vector<uint8_t> &data, bool) {
        client_bytes_received += data.size();
        client_data_cv.notify_one();
      });

  client.SetFlowControlHandler([&]() {
    std::lock_guard<std::mutex> lock(client_mutex);
    flow_control_cv.notify_all();
  });

  client.SetErrorHandler([](int code, const std::string &msg) {
    std::cerr << "[Client Error] " << msg << " (Code: " << code << ")"
              << std::endl;
  });

  try {
    client.Start();
    std::cout << "[Client] Bound to port " << client.GetLocalPort()
              << std::endl;
    if (!client.Connect("127.0.0.1", server_port)) {
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
  double peak_send = 0.0, peak_recv = 0.0;

  std::cout << "[Client] Sending " << TOTAL_PACKETS << " packets of "
            << PACKET_SIZE << " bytes (" << (TOTAL_BYTES / (1024 * 1024))
            << " MB)..." << std::endl;

  if (use_backpressure) {
    std::cout << "[Client] Mode: backpressure-paced (one packet at a time)"
              << std::endl;
  } else {
    std::cout << "[Client] Mode: bulk (flow-control-paced)" << std::endl;
  }

  // Both modes use the same paced-send loop.
  // CanSendOnStream() checks the stream flow-control budget before each send,
  // preventing the congestion window from being overwhelmed.
  auto last_print = std::chrono::steady_clock::now();
  for (size_t i = 0; i < TOTAL_PACKETS; ++i) {
    bool is_last = (i == TOTAL_PACKETS - 1);

    // Block until stream has budget for one packet
    {
      std::unique_lock<std::mutex> lock(client_mutex);
      while (!client.CanSendOnStream(stream_id, PACKET_SIZE) &&
             client.GetConnectionState() == ConnectionState::Connected) {
        auto now = std::chrono::steady_clock::now();
        if (now - last_print > std::chrono::seconds(1)) {
          auto conn = client.GetConnection();
          if (conn) {
            auto stream = conn->GetStream(stream_id);
            if (stream) {
              std::cout << "[Client Debug] Blocked at packet " << i
                        << ". Stream offset: " << stream->GetSendOffset() << "/"
                        << stream->GetMaxSendOffset()
                        << ", Conn bytes: " << conn->GetTotalStreamBytesSent()
                        << "/" << conn->GetMaxSendData() << std::endl;
            }
          }
          last_print = now;
        }
        flow_control_cv.wait_for(lock, std::chrono::milliseconds(100));
      }
    }

    if (client.GetConnectionState() != ConnectionState::Connected) {
      std::cerr << "[Client] Connection lost at packet " << i << std::endl;
      break;
    }

    client.SendOnStream(stream_id, payload, is_last);

    double s = tracker.GetSendThroughputBytesPerSec();
    double r = tracker.GetRecvThroughputBytesPerSec();
    if (s > peak_send) peak_send = s;
    if (r > peak_recv) peak_recv = r;

    // Pacing delay to prevent OS socket buffer overflow and CPU saturation.
    auto delay_per_packet = use_backpressure ? std::chrono::microseconds(1000)
                                             : std::chrono::microseconds(500);
    PreciseSleepUntil(transfer_start + (i + 1) * delay_per_packet);
  }

  std::cout << "[Client] All packets queued. Waiting for full echo..."
            << std::endl;

  // Wait until every byte is echoed back (or the connection drops)
  auto wait_start = std::chrono::steady_clock::now();
  {
    std::unique_lock<std::mutex> lock(client_mutex);
    while (client_bytes_received.load() < TOTAL_BYTES &&
           client.GetConnectionState() == ConnectionState::Connected) {
      auto now = std::chrono::steady_clock::now();

      // Hard overall timeout (2 minutes)
      if (now - wait_start > std::chrono::seconds(120)) {
        std::cerr << "[Client] Hard timeout waiting for echo." << std::endl;
        break;
      }

      if (client_data_cv.wait_for(lock, std::chrono::seconds(30)) ==
          std::cv_status::timeout) {
        std::cout << "[Client] No new echo bytes for 30 s. Stopping."
                  << std::endl;
        break;
      }

      double s = tracker.GetSendThroughputBytesPerSec();
      double r = tracker.GetRecvThroughputBytesPerSec();
      if (s > peak_send) peak_send = s;
      if (r > peak_recv) peak_recv = r;
    }
  }

  auto transfer_end = std::chrono::steady_clock::now();
  double elapsed =
      std::chrono::duration<double>(transfer_end - transfer_start).count();

  auto stats = client.GetStats();
  client.Disconnect();
  client.Stop();
  std::cout << "[Client] Stopped." << std::endl;

  double avg_send = elapsed > 0 ? (stats.bytes_sent / elapsed) : 0.0;
  double avg_recv =
      elapsed > 0 ? (client_bytes_received.load() / elapsed) : 0.0;

  auto format_bytes = [](uint64_t b) {
    auto sc = ScaleBytes(b);
    char buf[128];
    snprintf(buf, sizeof(buf), "%.2f %s", sc.value, sc.unit);
    return std::string(buf);
  };
  auto format_tp = [](double bps) {
    auto sb = ScaleBytes(static_cast<uint64_t>(bps));
    auto sb2 = ScaleBits(bps * 8.0);
    char buf[128];
    snprintf(buf, sizeof(buf), "%.2f %s/s (%.2f %s)", sb.value, sb.unit,
             sb2.value, sb2.unit);
    return std::string(buf);
  };

  std::cout << "\n========================================" << std::endl;
  std::cout << "     QUIC CLIENT THROUGHPUT METRICS     " << std::endl;
  std::cout << "========================================" << std::endl;
  std::cout << "Transfer Duration:          " << elapsed << " seconds"
            << std::endl;
  std::cout << "Total Packets Sent:         " << stats.packets_sent
            << std::endl;
  std::cout << "Total Packets Received:     " << stats.packets_received
            << std::endl;
  std::cout << "Total Bytes Sent:           " << stats.bytes_sent << " ("
            << format_bytes(stats.bytes_sent) << ")" << std::endl;
  std::cout << "Total Bytes Received(Echo): " << client_bytes_received.load()
            << " (" << format_bytes(client_bytes_received.load()) << ")"
            << std::endl;
  std::cout << "Retransmissions:            " << stats.retransmissions
            << std::endl;
  std::cout << "Avg Send Throughput:        " << format_tp(avg_send)
            << std::endl;
  std::cout << "Avg Recv Throughput:        " << format_tp(avg_recv)
            << std::endl;
  std::cout << "Peak Send Throughput:       " << format_tp(peak_send)
            << std::endl;
  std::cout << "Peak Recv Throughput:       " << format_tp(peak_recv)
            << std::endl;
  std::cout << "========================================\n" << std::endl;

  // --- Reliability verdict ---
  uint64_t echo = client_bytes_received.load();
  if (echo == TOTAL_BYTES) {
    std::cout << "[PASS] All " << TOTAL_BYTES
              << " bytes echoed back successfully." << std::endl;
  } else {
    std::cout << "[FAIL] Expected " << TOTAL_BYTES << " bytes echoed, got "
              << echo << " (" << (TOTAL_BYTES - echo) << " bytes missing)."
              << std::endl;
  }
}

int main(int argc, char *argv[]) {
  if (argc > 1 && std::string(argv[1]) == "--backpressure") {
    use_backpressure = true;
    std::cout << "[Main] Using backpressure-paced packet transmission mode"
              << std::endl;
  } else {
    std::cout << "[Main] Using bulk payload transmission mode (default)"
              << std::endl;
    std::cout << "[Main] Tip: Run with '--backpressure' to test paced mode"
              << std::endl;
  }

  // Only show flow-control and connection lifecycle messages to keep output
  // clean
  SetLogger(
      [](LogSeverity severity, const std::string &cls, const std::string &msg) {
        if (severity >= LogSeverity::Warn || cls == "FlowControl" ||
            cls == "Main" || cls == "Client" || cls == "Server" ||
            cls == "QuicClient" || cls == "QuicServer") {
          std::cout << "[" << cls << "] " << msg << std::endl;
        }
      });

  std::thread server_thread(RunServer);
  {
    std::unique_lock<std::mutex> lock(server_mutex);
    server_startup_cv.wait_for(lock, std::chrono::seconds(5),
                               [] { return server_listening; });
  }
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

  std::cout << "\nTest completed." << std::endl;
  std::cout << "Total bytes received by Server: "
            << server_bytes_received.load() << " (" << buf_srv << ")"
            << std::endl;
  std::cout << "Total bytes received by Client: "
            << client_bytes_received.load() << " (" << buf_cli << ")"
            << std::endl;

  return (client_bytes_received.load() == TOTAL_BYTES) ? 0 : 1;
}
