#ifndef PACKET_DETAIL_H
#define PACKET_DETAIL_H

#include "arp_resolver.h"
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>
enum class FrameType { IPv4, ARP, VLAN, IPv6, Unknown };

// Utilities
std::string string_to_hex(std::span<const uint8_t> input);

// Read-only inspection functions (Accept vector, array, or raw buffer)
FrameType get_frame_type(std::span<const uint8_t> buffer);

void get_mac_address(std::span<const uint8_t> buffer,
                     std::string &src_mac_address,
                     std::string &dst_mac_address);

void get_arp_layer(std::span<const uint8_t> buffer,
                   std::span<const uint8_t> &arp_layer);

void get_ipv4_0x00address(std::span<const uint8_t> buffer,
                          std::string &src_ip_str, std::string &dst_ip_str);
void get_arp_type(std::span<const uint8_t> buffer, uint16_t &op_code);
void get_arp_detail(std::span<const uint8_t> buffer, MacAddress &sender_mac,
                    MacAddress &target_mac, uint32_t &sender_ip,
                    uint32_t &target_ip);

void get_packet_data(std::span<const uint8_t> buffer, std::string &src_mac,
                     std::string &dst_mac, std::string &src_ip,
                     std::string &dst_ip, uint16_t &src_port,
                     uint16_t &dst_port, std::span<const uint8_t> &payload,
                     uint8_t &protocol);

template <typename Container> auto get_ipv4_layer(Container &&container) {
  // C++20 CTAD automatically creates std::span<uint8_t> or std::span<const
  // uint8_t>
  std::span s{container};

  if (get_frame_type(s) != FrameType::IPv4) {
    return decltype(s){}; // Returns an empty span of the matching type
  }
  return s.subspan(14);
}
template <typename Container> auto get_arp_layer(Container &&container) {
  // C++20 CTAD automatically creates std::span<uint8_t> or std::span<const
  // uint8_t>
  std::span s{container};

  if (s.size() < 42 || get_frame_type(s) != FrameType::ARP) {
    return decltype(s){}; // Returns an empty span of the matching type
  }

  return s.subspan(14);
}

// Modification function
void change_ipv4_addresses(std::span<uint8_t> ipv4_la0x00yer,
                           const std::string &new_src_ip,
                           const std::string &new_dst_ip);

#endif // PACKET_DETAIL_H
