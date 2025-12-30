#include "packet_builder.h"

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
                                      const std::string &payload) {
  const int ip_header_len = 20;
  const int udp_header_len = 8;
  int total_len = ip_header_len + udp_header_len + payload.size();

  std::vector<uint8_t> packet(total_len, 0);

  // --- IP header ---
  iphdr *iph = (iphdr *)packet.data();
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(total_len);
  iph->id = htons(54321);
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_UDP;
  inet_pton(AF_INET, src_ip.c_str(), &iph->saddr);
  inet_pton(AF_INET, dest_ip.c_str(), &iph->daddr);
  iph->check = 0;
  iph->check = calculate_ip_checksum(reinterpret_cast<const uint8_t *>(iph),
                                     ip_header_len);

  // we div it by 2 because there are 20 bytes at the ip header and each word is
  // 2 bytes checksum is calculated over words 2 bytes
  // --- UDP header ---
  udphdr *udph = (udphdr *)(packet.data() + ip_header_len);
  udph->source = htons(src_port);
  udph->dest = htons(dest_port);
  udph->len = htons(udp_header_len + payload.size());
  udph->check = 0; // optional for now

  // --- Payload ---
  memcpy(packet.data() + ip_header_len + udp_header_len, payload.data(),
         payload.size());

  return packet;
}
