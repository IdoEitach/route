#include "../include/packet_detail.h"
#include <cstdint>

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

/// This function extracts the IPv4 address from the given buffer and converts
/// it to a string format. The function takes a pointer to the buffer containing
/// Parameters:
/// buffer: uint8_t pointer to the buffer containin the frame
/// ip_str: reference to a string where the extracted IP address will be stored
void get_ipv4_address(const uint8_t *buffer, std::string &src_ip_str,
                      std::string &dst_ip_str) {
  src_ip_str = std::to_string((int)(buffer[26])) + "." +
               std::to_string(((int)buffer[27])) + "." +
               std::to_string(((int)buffer[28])) + "." +
               std::to_string((int)buffer[29]);

  dst_ip_str = std::to_string((int)(buffer[30])) + "." +
               std::to_string(((int)buffer[31])) + "." +
               std::to_string(((int)buffer[32])) + "." +
               std::to_string((int)buffer[33]);
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
  std::cout << "frame data (first 14 bytes): ";
  for (int i = 0; i < 14; i++) {
    std::cout << std::hex << (int)buffer[i] << " ";
  }
  std::cout << std::dec << "end of packet" << std::endl;

  if (buffer.size() < 20) {
    throw std::runtime_error("Packet too small to contain IP .");
  }
  if (buffer[12] == 0x08 || buffer[13] == 0x00) {

    std::cout << std::endl;
    std::cout << "<============= new IPv4 packet detected. =================>"
              << std::endl;

    std::cout << "the ipv4 header (next 20 bytes): ";
    for (int i = 0; i <= 19; i++) {
      std::cout << (int)buffer[i + 14] << " ";
    }

    std::cout << std::hex << "Ethernet type: 0x" << (int)buffer[12]
              << (int)buffer[13] << std::dec << std::endl;

    get_mac_address(buffer, src_mac, dst_mac);
    get_ipv4_address(((uint8_t *)buffer.data()), src_ip, dst_ip);
    src_port = ntohs(*(uint16_t *)(buffer.data() + 20));
    dst_port = ntohs(*(uint16_t *)(buffer.data() + 22));
    payload = std::string(buffer.begin() + 28, buffer.end());

  } else if (buffer[12] == 0x80 && buffer[13] == 0x06) {
    std::cout << "Ethernet type: ARP" << std::endl;
  } else if (buffer[12] == 0x81 && buffer[13] == 0x00) {
    throw std::runtime_error("Vlan tagged packet, not supported yet.:)");
  } else if ((buffer[12] == 0x86 || buffer[13] == 0xdd)) {
    throw std::runtime_error(
        "Not an IPv4 packet. IPv6 is not supported yet.:)");
  }
}
