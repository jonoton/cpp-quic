#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <condition_variable>
#include <mutex>

#include "cppquic.hpp"

const int NUM_STREAMS = 4;
const size_t BYTES_PER_STREAM = 10000;
const size_t CHUNK_SIZE = 1000;

int main() {
  // Start server in a thread
  std::mutex server_mutex;
  std::condition_variable server_cv;
  bool server_listening = false;
  std::condition_variable server_connection_cv;
  bool client_connected = false;
  std::condition_variable server_data_cv;
  uint16_t server_port = 0;

  std::mutex client_mutex;
  std::condition_variable client_data_cv;

  std::atomic<uint64_t> server_bytes_received{0};

  std::thread server_thread([&]() {
    cppquic::QuicServer server(0);

    server.SetConnectionHandler([&](std::shared_ptr<cppquic::QuicConnection>) {
      std::lock_guard<std::mutex> lock(server_mutex);
      client_connected = true;
      server_connection_cv.notify_one();
    });

    // Subscribe to connection closed events to wake up the server thread
    // instantly on client disconnect
    cpppubsub::Worker event_worker;
    auto sub = server.GetEventBroker().Subscribe<cppquic::ConnectionEvent>(
        "connection_events");
    event_worker.AddSubscription<cppquic::ConnectionEvent>(
        sub, [&](const cppquic::ConnectionEvent &ev) {
          if (ev.state == cppquic::ConnectionState::Closed) {
            std::lock_guard<std::mutex> lock(server_mutex);
            server_data_cv.notify_all();
          }
        });
    event_worker.Start();

    server.SetStreamDataHandler(
        [&](std::shared_ptr<cppquic::QuicConnection> conn, uint64_t stream_id,
            const std::vector<uint8_t> &data, bool fin) {
          server_bytes_received += data.size();
          server.SendOnStream(conn, stream_id, data, fin);
          server_data_cv.notify_one();
        });

    server.Start();
    {
      std::lock_guard<std::mutex> lock(server_mutex);
      server_port = server.GetLocalPort();
      server_listening = true;
    }
    server_cv.notify_one();
    std::cout << "[Server] Listening on port " << server_port << "..."
              << std::endl;

    // Wait for client to connect
    {
      std::unique_lock<std::mutex> lock(server_mutex);
      server_connection_cv.wait_for(lock, std::chrono::seconds(10),
                                    [&] { return client_connected; });
    }

    // Wait for client to disconnect or timeout
    {
      std::unique_lock<std::mutex> lock(server_mutex);
      while (server.GetActiveConnectionCount() > 0) {
        if (server_data_cv.wait_for(lock, std::chrono::seconds(15)) ==
            std::cv_status::timeout) {
          break;
        }
      }
    }

    server.Stop();
    std::cout << "[Server] Stopped." << std::endl;
  });

  // Wait for server to be ready
  {
    std::unique_lock<std::mutex> lock(server_mutex);
    server_cv.wait_for(lock, std::chrono::seconds(5),
                       [&] { return server_listening; });
  }

  // Client
  cppquic::QuicClient client;
  std::atomic<uint64_t> client_bytes_received{0};

  client.SetStreamDataHandler(
      [&](uint64_t stream_id, const std::vector<uint8_t> &data, bool fin) {
        client_bytes_received += data.size();
        client_data_cv.notify_one();
      });

  try {
    client.Start();

    if (!client.Connect("127.0.0.1", server_port)) {
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
      auto target_time = transfer_start + (sent / CHUNK_SIZE + 1) *
                                              std::chrono::microseconds(100);
      cppquic::PreciseSleepUntil(target_time);
    }

    std::cout << "[Client] All data sent. Waiting for echoes..." << std::endl;

    // Wait for echo data
    uint64_t expected = NUM_STREAMS * BYTES_PER_STREAM;
    auto wait_start = std::chrono::steady_clock::now();
    {
      std::unique_lock<std::mutex> lock(client_mutex);
      while (client_bytes_received < expected) {
        if (client_data_cv.wait_for(lock, std::chrono::seconds(10)) ==
            std::cv_status::timeout) {
          break;
        }
      }
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
