#include <../include/rawsock.h>
#include <cstddef>
#include <cstdint>
#include <endian.h>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

void RawSocket::open_raw_socket(int domain, int protocol) {
  this->sockfd_ = socket((domain), SOCK_RAW, protocol);
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

void RawSocket::sniff_packets(std::string interface_name) {

  sockaddr_ll socket_address{};
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons(ETH_P_ALL);
  socket_address.sll_ifindex = if_nametoindex(interface_name.c_str());
  if (socket_address.sll_ifindex == 0) {
    throw std::runtime_error("Interface not found: " + interface_name);
  }

  socket_address.sll_ifindex = if_nametoindex(interface_name.c_str());

  this->open_raw_socket(AF_PACKET, ETH_P_ALL);

  if (bind(this->sockfd_, reinterpret_cast<sockaddr *>(&socket_address),
           sizeof(socket_address)) < 0) {
    std::cout << "the error is :" << errno << std::endl;
    throw std::runtime_error(
        "Failed to bind socket to interface: " + interface_name + "\n" +
        std::to_string(this->sockfd_));
  }

  packet_mreq mreq{};
  mreq.mr_ifindex = socket_address.sll_ifindex;
  mreq.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(this->sockfd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
                 sizeof(mreq)) < 0) {
    throw std::runtime_error("Failed to set promiscuous mode");
  }

  std::cout << "ifindex=" << socket_address.sll_ifindex
            << " sll_protocol(host)=" << ntohs(socket_address.sll_protocol)
            << std::endl;

  std::cout << "Sniffing on interface: " << interface_name << std::endl;
  while (true) {
    std::vector<uint8_t> buffer(65536);

    ssize_t num_bytes = recvfrom(this->sockfd_, buffer.data(), buffer.size(), 0,
                                 nullptr, nullptr);
    std::cout << "Received packet of size: " << num_bytes << " bytes"
              << std::endl;
    if (num_bytes < 0) {
      throw std::runtime_error("Failed to receive packet");
    }
    std::string src_ip, dst_ip, payload;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    get_packet_data(buffer, src_ip, dst_ip, src_port, dst_port, payload,
                    protocol);
    std::cout << "Received packet: " << num_bytes << " bytes" << std::endl;
    std::cout << "Src IP: " << src_ip << ",Dst IP: " << dst_ip
              << ", Src Port: " << src_port << ", Dst Port: " << dst_port
              << ", Protocol: " << (int)protocol << ", Payload: " << payload
              << std::endl;
  }
}
