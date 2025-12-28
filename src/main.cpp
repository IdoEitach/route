#include "../include/packet_builder.h"
#include <iostream>
#include <stdlib.h>
// #include "rawsock.h"
// #include "forward.h"
#include "../include/hash_table.h"

int main() {

  const std::string src_ip = "10.100.102.3";
  const std::string dst_ip = "10.100.102.12";
  uint16_t src_port = 12345;
  uint16_t dst_port = 80;
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

  return 0;
}
