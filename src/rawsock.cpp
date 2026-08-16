#include "packet_detail.h"
#include <../include/rawsock.h>
#include <cstddef>
#include <string>
#include <sys/socket.h>

void RawSocket::open_raw_socket(int domain, int protocol) {
  this->sockfd_ = socket((domain), SOCK_RAW, protocol);
  std::cout << "Socket FD: " << this->sockfd_ << std::endl;
  if (this->sockfd_ < 0) {
    throw std::runtime_error("Socket creation failed");
  }
}

/// This function is for ensuring a raw socket is created for sniffing. if not
/// it will creat it Params: interface_name: the name of the interface tmmsghdro

void RawSocket::send_raw_packet(const uint8_t *packet, size_t packet_len,
                                const std::string &interface_name) {

  ensure_socket(interface_name);

  struct sockaddr_ll loc_addr = {};
  loc_addr.sll_family = AF_PACKET;
  loc_addr.sll_ifindex = if_nametoindex(interface_name.c_str());
  loc_addr.sll_halen = ETH_ALEN;

  // The first 6 bytes of an Ethernet frame are the destination MAC address
  std::memcpy(loc_addr.sll_addr, packet, 6);

  ssize_t bytes_sent = sendto(this->sockfd_, packet, packet_len, 0,
                              (struct sockaddr *)&loc_addr, sizeof(loc_addr));

  if (bytes_sent < 0) {
    throw std::runtime_error("Failed to send packet from socket fd " +
                             std::to_string(this->sockfd_) +
                             " | Error: " + std::strerror(errno));
  }
}
/// sniff on.
void RawSocket::ensure_socket(const std::string &interface_name) {
  if (this->sockfd_ > 0) {
    return;
  }

  this->open_raw_socket(AF_PACKET, ETH_P_ALL);

  sockaddr_ll socket_address{};
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons(ETH_P_ALL);
  socket_address.sll_ifindex = if_nametoindex(interface_name.c_str());
  if (socket_address.sll_ifindex == 0) {
    throw std::runtime_error("Interface not found: " + interface_name);
  }

  socket_address.sll_ifindex = if_nametoindex(interface_name.c_str());

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
}

int RawSocket::sniff_packets_batch(const std::string &interface_name,
                                   PacketBatch &packet_batch,
                                   unsigned int timeout_ms) {
  ensure_socket(interface_name);
  timespec time_out{};
  time_out.tv_sec = timeout_ms / 1000;
  time_out.tv_nsec = (timeout_ms % 1000) * 1000000;
  packet_batch.reset_for_recv(65536);
  // std::cout << "Sniffing on interface in batch: " << interface_name
  //           << std::endl;
  int n = 0;

  n = recvmmsg(this->sockfd_, packet_batch.msgs.data(), packet_batch.batch_size,
               0, &time_out);
  if (n <= 0) {
    std::cout << "No packets received in the batch." << std::endl;

    return 0;
  }

  packet_batch.packets_received = n;

  return n;
}

int RawSocket::sniff_packets(const std::string &interface_name,
                             std::vector<uint8_t> &buffer) {
  ensure_socket(interface_name);
  std::cout << "Sniffing on interface: " << interface_name << std::endl;

  ssize_t num_bytes = recvfrom(this->sockfd_, buffer.data(), buffer.size(), 0,
                               nullptr, nullptr);
  if (num_bytes < 0) {
    throw std::runtime_error("Failed to receive packet");
  }
  buffer.resize(num_bytes);
  std::string src_mac, dst_mac, src_ip, dst_ip, payload;
  uint16_t src_port, dst_port;
  uint8_t protocol;

  FrameType frameType = get_frame_type(buffer);
  if (frameType != FrameType::IPv4) {

    std::cout << "Non-IPv4 packet received, skipping..." << std::endl;
    return 0;
  }

  return 1;
}
