#include <iostream>
#include <string>

#include "cppquic.hpp"

int main() {
  cppquic::QuicServer server(4433);

  server.SetConnectionHandler(
      [](std::shared_ptr<cppquic::QuicConnection> conn) {
        std::cout << "New QUIC connection from " << conn->GetPeer().ToString()
                  << " [" << conn->GetLocalConnectionId().ToHex() << "]"
                  << std::endl;
      });

  server.SetStreamDataHandler(
      [&server](std::shared_ptr<cppquic::QuicConnection> conn,
                uint64_t stream_id, const std::vector<uint8_t> &data,
                bool fin) {
        std::string text(data.begin(), data.end());
        std::cout << "Stream " << stream_id << " from "
                  << conn->GetPeer().ToString() << ": " << text << std::endl;

        // Echo back on the same stream
        server.SendOnStream(conn, stream_id, "Echo: " + text, fin);
      });

  server.SetErrorHandler([](int code, const std::string &msg) {
    std::cerr << "[Server Error] " << msg << " (Code: " << code << ")"
              << std::endl;
  });

  cpppubsub::Worker worker;
  auto sub = server.GetEventBroker().Subscribe<cppquic::ConnectionEvent>(
      "connection_events");
  worker.AddSubscription<cppquic::ConnectionEvent>(
      sub, [](const cppquic::ConnectionEvent &event) {
        std::string state_str =
            event.state == cppquic::ConnectionState::Connected ? "Connected"
                                                               : "Closed";
        std::cout << "Connection event [" << event.connection_id.ToHex()
                  << "]: " << state_str << " from " << event.peer.ToString()
                  << std::endl;
      });
  worker.Start();

  try {
    server.Start();
    std::cout << "QUIC Server running on port 4433. Press Enter to stop."
              << std::endl;
    std::cin.get();
    server.Stop();
  } catch (const std::exception &e) {
    std::cerr << "Failed to start server: " << e.what() << std::endl;
  }

  worker.Stop();
  return 0;
}
