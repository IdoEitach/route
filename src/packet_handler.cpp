#include "../include/packet_handler.h"

bool handle_ipv4(std::span<uint8_t> packet, PacketContext &ctx) {
  // Implement IPv4 packet handling logic here
  // std::cout << "Handling IPv4 packet of size: " << packet.size() <<
  // std::endl;

  std::string src_mac, dst_mac, src_ip, dst_ip;
  std::span<const uint8_t> payload;
  uint16_t src_port = 0, dst_port = 0;
  uint8_t protocol = 0;

  change_mac_addresses(packet, {0x00, 0x45, 0xe2, 0x0f, 0x67, 0xdd},
                       {0x30, 0xe3, 0xa4, 0xdd, 0xab, 0xc1});
  std::span<uint8_t> ipv4_pointer = get_ipv4_layer(packet);
  change_ipv4_addresses(ipv4_pointer, 0x0666640A, 0x0D66640A); // Change to

  get_packet_data(packet, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                  payload, protocol);

  // std::cout << "[IPv4] Src IP: " << src_ip << ", Dst IP: " << dst_ip
  //         << std::endl;
  return true; // Indicate successful handling
}

bool handle_arp(std::span<uint8_t> packet, PacketContext &ctx) {
  // Implement ARP packet handling logic here
  std::cout << "Handling ARP packet of size: " << packet.size() << std::endl;
  // For example, you might want to parse the ARP header and respond if
  // necessary.

  uint16_t op_code;

  std::span<const uint8_t> arp_layer;
  arp_layer = get_arp_layer(packet);
  get_arp_type(arp_layer, op_code);

  std::cout << "[ARP] Operation Code: " << op_code << std::endl;
  return false;
}
