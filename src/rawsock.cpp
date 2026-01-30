#include <../include/rawsock.h>
#include <netinet/in.h>

void RawSocket::open_raw_socket() {
  this->sockfd_ = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  std::cout << "Socket FD: " << this->sockfd_ << std::endl;
  if (this->sockfd_ < 0) {
    throw std::runtime_error("Socket creation failed");
  }
}

void RawSocket::send_raw_packet(const uint8_t *packet, size_t packet_len) {
  // Implementation of sending raw packet goes here
  std::string dest_ip =
      std::to_string(packet[16]) + "." + std::to_string(packet[17]) + "." +
      std::to_string(packet[18]) + "." + std::to_string(packet[19]);
  std::uint16_t dest_port = (*(uint16_t *)(packet + 22));

  struct sockaddr_in dst;
  dst.sin_family = AF_INET;
  dst.sin_port = htons(dest_port);
  dst.sin_addr.s_addr = inet_addr(dest_ip.c_str());

  ssize_t bytes_sent = sendto(this->sockfd_, packet, packet_len, 0,
                              (struct sockaddr *)&dst, sizeof(dst));

  if (bytes_sent < 0) {
    throw std::runtime_error("Failed to send packet");
  }
}
