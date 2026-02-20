#include "../include/packet_detail.h"

void get_mac_address(const std::vector<uint8_t> &buffer,
                     std::string &src_mac_address,
                     std::string &dst_mac_address) {
  if (buffer.size() < 14) {
    throw std::runtime_error("Packet too small to contain Ethernet header.");
  }

  src_mac_address.clear();
  dst_mac_address.clear();

  std::ostringstream oss;

  for (int i = 0; i < 6; ++i) {
    if (i > 0)
      dst_mac_address += ":";
    oss.str("");
    oss << std::hex << static_cast<int>(buffer[i]);
    dst_mac_address += oss.str();
  }
  for (int i = 6; i < 12; ++i) {
    if (i > 6)
      src_mac_address += ":";
    oss.str("");
    oss << std::hex << static_cast<int>(buffer[i]);
    src_mac_address += oss.str();
  }
}

void get_ipv4_address(const uint32_t *buffer, std::string &ip_str) {
  ip_str = std::to_string((buffer[0] >> 24) & 0xFF) + "." +
           std::to_string((buffer[0] >> 16) & 0xFF) + "." +
           std::to_string((buffer[0] >> 8) & 0xff) + "." +
           std::to_string(buffer[0] & 0xFF);
}

/// This function extracts the source and destination MAC addresses, source
/// and Params: destination IP addresses, source and destination ports,
/// payload, protocol Expexcptions:
/// - If the packet is too small to contain an IP header, it throws a
/// runtime_error
/// - If the Ethernet type is not IPv4, it throws a runtime_error
/// - If the packet is too small to contain IP and UDP headers, it throws an
/// invalid_argument
void get_packet_data(const std::vector<uint8_t> &buffer, std::string &src_mac,
                     std::string &dst_mac, std::string &src_ip,
                     std::string &dst_ip, uint16_t &src_port,
                     uint16_t &dst_port, std::string &payload,
                     uint8_t &protocol) {
  std::cout << "Packet data (first 32 bytes): ";
  for (int i = 0; i < 32; i++) {
    std::cout << std::hex << (int)buffer[i] << " ";
  }
  std::cout << std::dec << "end of packet" << std::endl;

  if (buffer.size() < 20) {
    throw std::runtime_error("Packet too small to contain IP .");
  }

  // getting the mac address
  get_mac_address(buffer, src_mac, dst_mac);

  if ((buffer[12] != 0x08 || buffer[13] != 0x00)) {
    std::cout << std::hex << "Ethernet type: 0x" << (int)buffer[12]
              << (int)buffer[13] << std::dec << std::endl;
    throw std::runtime_error("Not an IPv4 packet.");
  }

  get_ipv4_address((uint32_t *)((uint32_t *)buffer.data() + 26), src_ip);
  get_ipv4_address((uint32_t *)((uint32_t *)buffer.data() + 30), dst_ip);
  src_port = ntohs(*(uint16_t *)(buffer.data() + 20));
  dst_port = ntohs(*(uint16_t *)(buffer.data() + 22));
  payload = std::string(buffer.begin() + 28, buffer.end());
}
