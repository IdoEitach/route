#include "packet_builder.h"
#include <cstdint>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <vector>

uint16_t calculate_ip_checksum(const std::span<uint8_t> buf, int len) {
  uint32_t sum = 0;

  for (size_t i = 0; i < len; i += 2) {
    uint16_t word = (static_cast<uint16_t>(buf[i]) << 8) |
                    (static_cast<uint16_t>(buf[i + 1]));
    sum += word;
  }

  // if its not ipv4. it will not get to the if in ipv4 because its never odd
  if (len & 1)
    sum += static_cast<uint16_t>(buf[len - 1]) << 8;

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

std::vector<uint8_t> build_udp_packet(const std::string &src_ip,
                                      uint16_t src_port,
                                      const std::string &dest_ip,
                                      uint16_t dest_port,
                                      const std::string &data, uint8_t ttl) {
  const int ip_header_len = 20;
  const int udp_header_len = 8;
  int total_len = ip_header_len + udp_header_len + data.size();
  std::vector<uint8_t> packet(total_len, 0);

  // the headers pointers
  auto *iph = reinterpret_cast<iphdr *>(packet.data());
  auto *udph = reinterpret_cast<udphdr *>(packet.data() + ip_header_len);

  uint8_t *payload = packet.data() + (ip_header_len + udp_header_len);
  std::memcpy(payload, data.data(), data.size());

  // --- IP header ---
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(total_len);
  iph->id = htonl(54321);
  iph->frag_off = 0;
  iph->ttl = ttl;
  iph->protocol = IPPROTO_UDP;
  inet_pton(AF_INET, src_ip.c_str(), &iph->saddr);
  inet_pton(AF_INET, dest_ip.c_str(), &iph->daddr);
  iph->check = 0; // initial checksum
  // we div it by 2 because there are 20 bytes at the ip header and each word is
  // 2 bytes checksum is calculated over words 2 bytes
  // --- UDP header ---
  udph->source = htons(src_port);
  udph->dest = htons(dest_port);
  udph->len = htons(udp_header_len + data.size());
  udph->check = 0; // optional for now

  return packet;
}

/// this function removes the Ethernet layer so it will be sended as
/// IPPROTOO_RAW
void remove_ethernet_layer(std::vector<uint8_t> &buffer) {
  if (buffer.size() < 14) {
    throw std::runtime_error("Packet too small to contain Ethernet header.");
  }
  buffer.erase(buffer.begin(), buffer.begin() + 14);
}

void change_mac_addresses(std::span<uint8_t> buffer,
                          const MacAddress &new_src_mac,
                          const MacAddress &new_dst_mac) {
  if (buffer.size() < 14) {
    throw std::runtime_error("Packet too small to contain Ethernet header.");
  }

  // Change destination MAC address
  std::memcpy(buffer.data(), new_dst_mac.bytes.data(), 6);

  // Change source MAC address
  std::memcpy(buffer.data() + 6, new_src_mac.bytes.data(), 6);
}

void build_arp_request(std::vector<uint8_t> &packet, const uint32_t &src_ip,
                       const uint32_t &dst_ip, const MacAddress &src_mac) {
  build_arp_eth_layer(packet, src_mac);
  std::span<uint8_t> arp_layer;
  arp_layer = get_arp_layer(packet);

  build_arp_request_packet_layer(arp_layer, src_ip, dst_ip, src_mac);
}

void build_arp_eth_layer(std::vector<uint8_t> &packet,
                         const MacAddress &src_mac) {
  if (packet.size() < 14) {
    throw std::runtime_error("Packet too small to contain Ethernet header.");
  }

  // Ethernet header
  std::memset(packet.data(), 0xFF, 6); // Destination MAC: Broadcast
  std::memcpy(packet.data() + 6, src_mac.bytes.data(), 6); // Source MAC
  packet[12] = 0x08; // EtherType: ARP (0x0806)
  packet[13] = 0x06;
}

void build_arp_request_packet_layer(std::span<uint8_t> packet,
                                    const uint32_t &src_ip,
                                    const uint32_t &dst_ip,
                                    const MacAddress &src_mac) {
  if (packet.size() < 28) {
    throw std::runtime_error("Packet too small to contain ARP request.");
  }

  // ARP header
  packet[0] = 0x00; // Hardware type: Ethernet (1)
  packet[1] = 0x01;
  packet[2] = 0x08; // Protocol type: IPv4 (0x0800)
  packet[3] = 0x00;
  packet[4] = 0x06; // Hardware size: MAC length (6)
  packet[5] = 0x04; // Protocol size: IPv4 length (4)
  packet[6] = 0x00; // Opcode: Request (1)
  packet[7] = 0x01;
  uint32_t big_endian_src_ip = htonl(src_ip);
  uint32_t big_endian_dst_ip = htonl(dst_ip);
  memcpy(packet.data() + 8, src_mac.bytes.data(), 6); // Sender MAC: Unknown
  memcpy(packet.data() + 14, &big_endian_src_ip, 4);  // Sender IP: Unknown
  std::memset(packet.data() + 18, 0x00, 6);           // Target MAC: Unknown
  memcpy(packet.data() + 24, &big_endian_dst_ip, 4);
}

///< summary>
/// This function changes the source and destination IPv4 addresses in the given
/// packet buff er and recalculates the IP header checksum.
/// vector<unint8_t> buffer- a raw ip header packet
/// attention: this functino gets a little endian and in the packet its big
/// endian
void change_ipv4_addresses(std::span<uint8_t> buffer,
                           const uint32_t &new_src_ip,
                           const uint32_t &new_dst_ip) {
  if (buffer.size() < 20) {
    throw std::runtime_error("Packet too small to contain IP header.");
  }

  struct iphdr *ip = reinterpret_cast<struct iphdr *>(buffer.data());

  if (ip->version != 4) {
    throw std::runtime_error("Not an IPv4 packet");
  }

  ip->saddr = new_src_ip;
  ip->daddr = new_dst_ip;
  ip->check = 0;
  ip->check = calculate_ip_checksum(buffer, ip->ihl * 4);
}
