// #include "../include/packet_builder.h"
// #include "../include/rawsock.h"
// #include <iostream>
// #include <stdlib.h>
// // #include "forward.h"
// #include "../include/hash_table.h"
//
// int main() {
//
//   const std::string src_ip = "10.100.102.16";
//   const std::string dst_ip = "10.100.102.6";
//   uint16_t src_port = 12345;
//   uint16_t dst_port = 55555;
//
//   const std::string payload = "Hello, UDP!";
//
//   std::vector<uint8_t> packet =
//       build_udp_packet(src_ip, src_port, dst_ip, dst_port, payload);
//
//   std::cout << "Built UDP packet of size: " << packet.size() << " bytes"
//             << std::endl;
//   try {
//     print_packet(packet);
//   } catch (std::invalid_argument &e) {
//     std::cerr << "Error printing packet: " << e.what() << std::endl;
//   }
//   RawSocket raw_socket = RawSocket();
//
//   try {
//     raw_socket.open_raw_socket();
//     raw_socket.send_raw_packet(packet.data(), packet.size());
//
//     std::cout << "Packet sent successfully!" << std::endl;
//   } catch (const std::exception &e) {
//     std::cerr << "Error sending packet: " << e.what() << std::endl;
//     return EXIT_FAILURE;
//   }
//
//   return 0;
// }
//
//
//
//

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

// Checksum calculation function
unsigned short checksum(void *b, int len) {
  unsigned short *buf = (unsigned short *)b;
  unsigned int sum = 0;
  unsigned short result;
  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

int main() {
  // 1. Create a raw socket (requires root)
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) {
    perror("Socket creation failed");
    return 1;
  }

  // 2. Destination Info
  std::string target_ip = "172.20.10.8";
  int target_port = 5000;
  char data[] = "Hello Raw UDP";

  char packet[4096]; // Buffer for full packet
  memset(packet, 0, 4096);

  // Pointers to headers
  struct iphdr *iph = (struct iphdr *)packet;
  struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
  char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
  strcpy(payload, data);

  // 3. Fill in IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data);
  iph->id = htonl(54321);
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = 253;
  iph->saddr = inet_addr("172.20.10.2"); // Source IP
  iph->daddr = inet_addr(target_ip.c_str());
  iph->check = 0; // Kernel will fill this if 0

  // 4. Fill in UDP Header
  udph->source = htons(12345); // Source Port
  udph->dest = htons(target_port);
  udph->len = htons(sizeof(struct udphdr) + strlen(data));
  udph->check = 0; // Checksum optional for UDP over IPv4

  // 5. Setup destination address structure
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(target_port);
  sin.sin_addr.s_addr = inet_addr(target_ip.c_str());

  // 6. Send packet
  if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&sin,
             sizeof(sin)) < 0) {
    perror("sendto failed");
  } else {
    std::cout << "Raw UDP packet sent." << target_ip << std::endl;
  }

  close(sock);
  return 0;
}
