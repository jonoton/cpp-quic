#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "cppquic.hpp"

const int NUM_STREAMS = 4;
const size_t BYTES_PER_STREAM = 10000;
const size_t CHUNK_SIZE = 1000;

int main() {
  // Start server in a thread
  std::atomic<bool> server_ready{false};
  std::atomic<uint64_t> server_bytes_received{0};

  std::thread server_thread([&]() {
    cppquic::QuicServer server(4434);

    server.SetStreamDataHandler(
        [&server, &server_bytes_received](
            std::shared_ptr<cppquic::QuicConnection> conn, uint64_t stream_id,
            const std::vector<uint8_t> &data, bool fin) {
          server_bytes_received += data.size();
          // Echo back
          server.SendOnStream(conn, stream_id, data, fin);
        });

    server.Start();
    server_ready.store(true);
    std::cout << "[Server] Listening on port 4434..." << std::endl;

    auto start = std::chrono::steady_clock::now();
    // Wait for client to connect
    while (server.GetActiveConnectionCount() == 0) {
      if (std::chrono::steady_clock::now() - start > std::chrono::seconds(10)) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Wait for client to disconnect or timeout
    auto last_activity = std::chrono::steady_clock::now();
    while (server.GetActiveConnectionCount() > 0) {
      if (std::chrono::steady_clock::now() - last_activity >
          std::chrono::seconds(15)) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    server.Stop();
    std::cout << "[Server] Stopped." << std::endl;
  });

  // Wait for server to be ready
  while (!server_ready.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Client
  cppquic::QuicClient client;
  std::atomic<uint64_t> client_bytes_received{0};

  client.SetStreamDataHandler(
      [&client_bytes_received](uint64_t stream_id,
                               const std::vector<uint8_t> &data, bool fin) {
        client_bytes_received += data.size();
      });

  try {
    client.Start();

    if (!client.Connect("127.0.0.1", 4434)) {
      std::cerr << "[Client] Failed to connect." << std::endl;
      server_thread.join();
      return 1;
    }

    std::cout << "[Client] Connected! Opening " << NUM_STREAMS << " streams..."
              << std::endl;

    auto transfer_start = std::chrono::steady_clock::now();

    // Open multiple streams and send data on each
    std::vector<uint64_t> stream_ids;
    for (int i = 0; i < NUM_STREAMS; ++i) {
      stream_ids.push_back(client.OpenStream(true));
    }

    std::vector<uint8_t> chunk(CHUNK_SIZE, 'A');
    for (size_t sent = 0; sent < BYTES_PER_STREAM; sent += CHUNK_SIZE) {
      for (auto stream_id : stream_ids) {
        bool is_last = (sent + CHUNK_SIZE >= BYTES_PER_STREAM);
        client.SendOnStream(stream_id, chunk, is_last);
      }
      std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    std::cout << "[Client] All data sent. Waiting for echoes..." << std::endl;

    // Wait for echo data
    uint64_t expected = NUM_STREAMS * BYTES_PER_STREAM;
    auto wait_start = std::chrono::steady_clock::now();
    while (client_bytes_received < expected) {
      if (std::chrono::steady_clock::now() - wait_start >
          std::chrono::seconds(10)) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    auto transfer_end = std::chrono::steady_clock::now();
    double elapsed =
        std::chrono::duration<double>(transfer_end - transfer_start).count();

    auto stats = client.GetStats();

    std::cout << "\n======================================" << std::endl;
    std::cout << "   MULTI-STREAM TRANSFER METRICS     " << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << "Streams: " << NUM_STREAMS << std::endl;
    std::cout << "Bytes per stream: " << BYTES_PER_STREAM << std::endl;
    std::cout << "Total bytes sent: " << stats.bytes_sent << std::endl;
    std::cout << "Total bytes received: " << client_bytes_received.load()
              << std::endl;
    std::cout << "Elapsed: " << elapsed << " seconds" << std::endl;

    auto scaled_send =
        cppquic::ScaleBytes(static_cast<uint64_t>(stats.bytes_sent / elapsed));
    std::cout << "Avg send throughput: " << scaled_send.value << " "
              << scaled_send.unit << "/s" << std::endl;

    auto scaled_recv = cppquic::ScaleBytes(
        static_cast<uint64_t>(client_bytes_received.load() / elapsed));
    std::cout << "Avg recv throughput: " << scaled_recv.value << " "
              << scaled_recv.unit << "/s" << std::endl;
    std::cout << "Retransmissions: " << stats.retransmissions << std::endl;
    std::cout << "======================================\n" << std::endl;

    client.Disconnect();
    client.Stop();
  } catch (const std::exception &e) {
    std::cerr << "[Client] Failed: " << e.what() << std::endl;
  }

  server_thread.join();
  return 0;
}
