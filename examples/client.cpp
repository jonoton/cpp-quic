#include <iostream>
#include <string>
#include <thread>

#include "cppquic.hpp"

int main() {
  cppquic::QuicClient client;

  client.SetStreamDataHandler(
      [](uint64_t stream_id, const std::vector<uint8_t> &data, bool fin) {
        std::string text(data.begin(), data.end());
        std::cout << "Stream " << stream_id << " response: " << text
                  << (fin ? " [FIN]" : "") << std::endl;
      });

  client.SetErrorHandler([](int code, const std::string &msg) {
    std::cerr << "[Client Error] " << msg << " (Code: " << code << ")"
              << std::endl;
  });

  try {
    client.Start();
    std::cout << "Client bound to port: " << client.GetLocalPort() << std::endl;

    if (!client.Connect("127.0.0.1", 4433)) {
      std::cerr << "Failed to connect to server." << std::endl;
      client.Stop();
      return 1;
    }

    std::cout << "Connected to server!" << std::endl;

    // Open a bidirectional stream and send a message
    uint64_t stream_id = client.OpenStream(true);
    client.SendOnStream(stream_id, "Hello QUIC Server!");

    std::cout << "Sent message on stream " << stream_id
              << ". Press Enter to exit." << std::endl;
    std::cin.get();

    client.Disconnect();
    client.Stop();
  } catch (const std::exception &e) {
    std::cerr << "Failed: " << e.what() << std::endl;
  }

  return 0;
}
