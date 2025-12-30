#include <../include/rawsock.h>

void RawSocket::open_raw_socket(int *out_fd) {

  if (!out_fd) {
    throw std::invalid_argument("Output file descriptor pointer is null");
  }

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  if (sockfd < 0) {
    throw std::runtime_error("Socket creation failed");
  }

  *out_fd = sockfd;
}

void RawSocket::send_raw_packet(const uint8_t *packet, size_t packet_len) {
  // Implementation of sending raw packet goes here
  std::string dest_ip =
      std::to_string(packet[12]) + "." + std::to_string(packet[13]) + "." +
      std::to_string(packet[14]) + "." + std::to_string(packet[15]);

  sockaddr_in dst{};
  dst.sin_family = AF_INET;

  if (inet_pton(AF_INET, dest_ip.c_str(), &dst.sin_addr) != 1) {
    throw std::runtime_error("Invalid destination IP address");
  }

  ssize_t bytes_sent = sendto(sockfd, packet, packet_len, 0,
                              (struct sockaddr *)&dst, sizeof(dst));

  if (bytes_sent < 0) {
    throw std::runtime_error("Failed to send packet");
  }
}
