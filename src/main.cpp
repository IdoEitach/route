#include "../include/packet_builder.h"
#include "../include/rawsock.h"
#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
// #include "forward.h"
#include "../include/hash_table.h"

int main() {

  const std::string src_ip = "10.100.102.21";
  const std::string dst_ip = "10.100.102.13";
  uint16_t src_port = 12345;
  uint16_t dst_port = 55555;
  constexpr unsigned int BATCH_SIZE = 10;
  constexpr unsigned int TIMEOUT_MS = 10000;
  std::vector<std::vector<uint8_t>> packet_batch;

  const std::string payload = "Hello, UDP!";

  std::string src_ip_sniff, dst_ip_sniff, payload_sniff;
  std::string src_mac_sniff, dst_mac_sniff;
  uint16_t src_port_sniff, dst_port_sniff;
  uint8_t protocol_sniff;

  std::vector<uint8_t> packet =
      build_udp_packet(src_ip, src_port, dst_ip, dst_port, payload, 255);

  std::cout << "Built UDP packet of size: " << packet.size() << " bytes"
            << std::endl;
  try {
    print_packet(packet);
  } catch (std::invalid_argument &e) {
    std::cerr << "Error printing packet: " << e.what() << std::endl;
  }
  RawSocket raw_socket = RawSocket();

  try {

    raw_socket.open_raw_socket(AF_INET, IPPROTO_RAW);
    raw_socket.send_raw_packet(packet.data(), packet.size());

    std::cout << "Packet sent successfully!" << std::endl;
  } catch (const std::exception &e) {

    std::cerr << "Error sending packet: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  RawSocket sniffer_socket = RawSocket();
  std::string interface_name = "wlp1s0";
  std::vector<uint8_t> buffer(65536);
  try {
    try {
      sniffer_socket.ensure_socket(interface_name);
    } catch (const std::exception &e) {
      std::cerr << "Error ensuring socket: " << e.what() << std::endl;
    }
    int packets_received = sniffer_socket.sniff_packets_batch(
        interface_name, packet_batch, BATCH_SIZE, TIMEOUT_MS);
    if (packets_received <= 0) {
      std::cout << "No packets received in the batch." << std::endl;
      return EXIT_SUCCESS;
    }
    for (int i = 0; i < packets_received; ++i) {
      std::cout << "Packet " << i + 1
                << " received, size: " << packet_batch[i].data() << " bytes"
                << std::endl;
      get_packet_data(packet_batch[i], src_mac_sniff, dst_mac_sniff,
                      src_ip_sniff, dst_ip_sniff, src_port_sniff,
                      dst_port_sniff, payload_sniff, protocol_sniff);
      try {
        std::cout << "Packet " << i + 1 << " content: ";
      } catch (std::invalid_argument &e) {
        std::cerr << "Error printing packet: " << e.what() << std::endl;
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "Error sniffing packets: " << e.what() << std::endl;
  }
  std::cout << "well its done" << std::endl;
  return 0;
}
