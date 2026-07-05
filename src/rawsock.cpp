#include "packet_detail.h"
#include <../include/rawsock.h>
#include <cstddef>
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

/// This function is for ensuring a raw socket is created for sniffing. if not
/// it will creat it Params: interface_name: the name of the interface tmmsghdro
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
}

int RawSocket::sniff_packets_batch(const std::string &interface_name,
                                   std::vector<std::vector<uint8_t>> &packets,
                                   unsigned int batch_size,
                                   unsigned int timeout_ms) {
  ensure_socket(interface_name);
  timespec time_out{};
  std::vector<std::vector<uint8_t>> buffers(batch_size);

  time_out.tv_sec = timeout_ms / 1000;
  time_out.tv_nsec = (timeout_ms % 1000) * 1000000;
  if (packets.size() < batch_size) {
    packets.resize(batch_size);
  }
  for (size_t i = 0; i < batch_size; ++i) {
    // Ensure the vector has enough internal capacity for a max Ethernet frame
    if (packets[i].capacity() < 65536) {
      packets[i].reserve(65536);
    }
    // Temporarily set size to maximum so the kernel has room to write
    packets[i].resize(65536);
  }

  std::vector<iovec> iov(batch_size);
  std::vector<mmsghdr> msgs(batch_size);
  std::memset(msgs.data(), 0, sizeof(mmsghdr) * batch_size);

  for (size_t i = 0; i < batch_size; i++) {
    iov[i].iov_base = packets[i].data();
    iov[i].iov_len = packets[i].size();

    msgs[i].msg_hdr.msg_iov = &iov[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }

  std::cout << "Sniffing on interface in batch: " << interface_name
            << std::endl;
  int n = 0;
  n = recvmmsg(this->sockfd_, msgs.data(), batch_size, 0, &time_out);
  if (n <= 0) {
    std::cout << "No packets received in the batch." << std::endl;
    return 0;
  }

  for (int i = 0; i < n; i++) {
    packets[i].resize(msgs[i].msg_len);
  }

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

  get_packet_data(buffer, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                  payload, protocol);

  std::cout << "Src Mac: " << src_mac << ", Dst Mac: " << dst_mac << std::endl;
  std::cout << "Src IP: " << src_ip << ",Dst IP: " << dst_ip
            << ", Src Port: " << src_port << ", Dst Port: " << dst_port
            << ", Protocol: " << (int)protocol << ", Payload: " << payload
            << std::endl;
  return 1;
}
