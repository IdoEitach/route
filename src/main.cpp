#include "../include/packet_builder.h"
#include "../include/rawsock.h"
#include <iostream>
#include <stdlib.h>
// #include "forward.h"
#include "../include/hash_table.h"

int main() {

  const std::string src_ip = "10.100.102.21";
  const std::string dst_ip = "10.100.102.13";
  uint16_t src_port = 12345;
  uint16_t dst_port = 55555;

  const std::string payload = "Hello, UDP!";

  std::vector<uint8_t> packet =
      build_udp_packet(src_ip, src_port, dst_ip, dst_port, payload);

  std::cout << "Built UDP packet of size: " << packet.size() << " bytes"
            << std::endl;
  try {
    print_packet(packet);
  } catch (std::invalid_argument &e) {
    std::cerr << "Error printing packet: " << e.what() << std::endl;
  }
  RawSocket raw_socket = RawSocket();

  try {
    raw_socket.open_raw_socket();
    raw_socket.send_raw_packet(packet.data(), packet.size());

    std::cout << "Packet sent successfully!" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Error sending packet: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return 0;
}
