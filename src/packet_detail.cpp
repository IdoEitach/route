#include "../include/packet_detail.h"
#include <arpa/inet.h>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>

std::string string_to_hex(std::span<const uint8_t> input) {
  std::ostringstream ss;
  for (uint8_t c : input) {
    ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c)
       << " ";
  }
  return ss.str();
}

FrameType get_frame_type(std::span<const uint8_t> buffer) {
  if (buffer.size() < 14) {
    throw std::runtime_error("Packet too small to contain Ethernet header.");
  }

  uint16_t eth_type = (static_cast<uint16_t>(buffer[12]) << 8) | buffer[13];

  switch (eth_type) {
  case 0x0800:
    return FrameType::IPv4;
  case 0x0806:
    return FrameType::ARP;
  case 0x8100:
    return FrameType::VLAN;
  case 0x86DD:
    return FrameType::IPv6;
  default:
    return FrameType::Unknown;
  }
}

void get_mac_address(std::span<const uint8_t> buffer,
                     std::string &src_mac_address,
                     std::string &dst_mac_address) {
  if (buffer.size() < 14) {
    throw std::runtime_error("Packet too small to contain Ethernet header.");
  }

  std::ostringstream dst_oss, src_oss;
  for (int i = 0; i < 6; ++i) {
    if (i > 0)
      dst_oss << ":";
    dst_oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(buffer[i]);
  }
  for (int i = 6; i < 12; ++i) {
    if (i > 6)
      src_oss << ":";
    src_oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(buffer[i]);
  }

  dst_mac_address = dst_oss.str();
  src_mac_address = src_oss.str();
}

void get_ipv4_address(std::span<const uint8_t> buffer, std::string &src_ip_str,
                      std::string &dst_ip_str) {
  if (buffer.size() < 20) {
    throw std::runtime_error("Buffer too small for IPv4 header.");
  }

  src_ip_str = std::to_string(buffer[12]) + "." + std::to_string(buffer[13]) +
               "." + std::to_string(buffer[14]) + "." +
               std::to_string(buffer[15]);

  dst_ip_str = std::to_string(buffer[16]) + "." + std::to_string(buffer[17]) +
               "." + std::to_string(buffer[18]) + "." +
               std::to_string(buffer[19]);
}

void get_arp_type(std::span<const uint8_t> buffer, uint16_t &op_code) {

  if (buffer.size() < 28) {
    throw std::runtime_error("Buffer too small for ARP packet.");
  }

  uint16_t op_code_big_endian = *reinterpret_cast<const uint16_t *>(&buffer[6]);
  op_code = (op_code_big_endian >> 8) & 0x00FF |
            (op_code_big_endian << 8) & 0xFF00; // Convert to host byte order
}

void get_packet_data(std::span<const uint8_t> buffer, std::string &src_mac,
                     std::string &dst_mac, std::string &src_ip,
                     std::string &dst_ip, uint16_t &src_port,
                     uint16_t &dst_port, std::span<const uint8_t> &payload,
                     uint8_t &protocol) {
  if (buffer.size() < 14) {
    throw std::runtime_error("Packet too small to contain Ethernet header.");
  }

  FrameType type = get_frame_type(buffer);

  if (type == FrameType::IPv4) {
    std::span<const uint8_t> ipv4_layer = get_ipv4_layer(buffer);

    get_mac_address(buffer, src_mac, dst_mac);
    get_ipv4_address(ipv4_layer, src_ip, dst_ip);

    protocol = ipv4_layer[9]; // Protocol field in IPv4 header

    src_port = ntohs(*reinterpret_cast<const uint16_t *>(buffer.data() + 34));
    dst_port = ntohs(*reinterpret_cast<const uint16_t *>(buffer.data() + 36));

    if (buffer.size() > 42) {
      payload = buffer.subspan(42);
    } else {
      throw std::runtime_error("fram to small to contain payload");
    }
  } else if (type == FrameType::ARP) {
    get_mac_address(buffer, src_mac, dst_mac);
  } else {
    throw std::runtime_error("Unsupported or unknown packet type.");
  }
}
