#pragma once

#include "packet_builder.h"
#include "packet_detail.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <endian.h>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

class RawSocket {
public:
  RawSocket() : sockfd_(-1) {}
  ~RawSocket() = default;

  RawSocket(const RawSocket &) = delete;
  RawSocket &operator=(const RawSocket &) = delete;

  void open_raw_socket(int domain = AF_INET, int protocol = IPPROTO_RAW);
  void send_raw_packet(const uint8_t *packet, size_t packet_len);

  int sniff_packets_batch(const std::string &interface_name,
                          std::vector<std::vector<uint8_t>> &packets,
                          unsigned int batch_size, unsigned int timeout_ms);

  int sniff_packets(const std::string &interface_name,
                    std::vector<uint8_t> &buffer);
  void ensure_socket(const std::string &interface_name);

private:
  int sockfd_;
  std::string interface_name_;
};
