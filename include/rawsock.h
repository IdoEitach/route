#pragma once

#include "packet_builder.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
class RawSocket {
public:
  RawSocket() : sockfd_(-1) {}
  ~RawSocket() = default;

  RawSocket(const RawSocket &) = delete;
  RawSocket &operator=(const RawSocket &) = delete;

  void open_raw_socket(int domain = AF_INET, int protocol = IPPROTO_RAW);
  void send_raw_packet(const uint8_t *packet, size_t packet_len);
  void sniff_packets(std::string interface_name);

private:
  int sockfd_;
};
