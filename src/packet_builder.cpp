#include "packet_builder.h"
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

uint16_t calculate_ip_checksum(const uint8_t *buf, int len) {
  uint32_t sum = 0;

  for (size_t i = 0; i < len; i += 2) {
    uint16_t word = (static_cast<uint16_t>(buf[i]) << 8) |
                    (static_cast<uint16_t>(buf[i + 1]));
    sum += word;
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return static_cast<uint16_t>(~sum);
}

void print_packet(const std::vector<uint8_t> &packet) {

  if (packet.size() < 28) {
    std::cout << "Packet too small to contain IP and UDP headers." << std::endl;
    throw std::invalid_argument("Packet too small");
  }

  // checksum print_packet
  uint16_t ip_checksum = ntohs(*(uint16_t *)(packet.data() + 10));
  std::cout << "IP Header Checksum: 0x" << std::hex << ip_checksum << std::dec
            << std::endl;
  std::cout << "src ip:" << (int)packet[12] << "." << (int)packet[13] << "."
            << (int)packet[14] << "." << (int)packet[15] << std::endl;
  std::cout << "dst ip:" << (int)packet[16] << "." << (int)packet[17] << "."
            << (int)packet[18] << "." << (int)packet[19] << std::endl;

  uint16_t src_port = ntohs(*(uint16_t *)(packet.data() + 20));
  uint16_t dst_port = ntohs(*(uint16_t *)(packet.data() + 22));

  std::cout << "src port: " << src_port << std::endl;
  std::cout << "dst port: " << dst_port << std::endl;
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

void get_packet_data(const std::vector<uint8_t> &buffer, std::string &src_ip,
                     std::string &dst_ip, uint16_t &src_port,
                     uint16_t &dst_port, std::string &payload,
                     uint8_t &protocol) {
  if (buffer.size() < 20) {
    throw std::invalid_argument("Packet too small to contain IP .");
  }

  src_ip = std::to_string(buffer[12]) + "." + std::to_string(buffer[13]) + "." +
           std::to_string(buffer[14]) + "." + std::to_string(buffer[15]);
  dst_ip = std::to_string(buffer[16]) + "." + std::to_string(buffer[17]) + "." +
           std::to_string(buffer[18]) + "." + std::to_string(buffer[19]);
  protocol = buffer[9];
  src_port = ntohs(*(uint16_t *)(buffer.data() + 20));
  dst_port = ntohs(*(uint16_t *)(buffer.data() + 22));

  payload = std::string(buffer.begin() + 28, buffer.end());
}
