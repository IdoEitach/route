#pragma once

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

class RawSocket {
public:
  RawSocket();
  ~RawSocket();

  RawSocket(const RawSocket &) = delete;
  RawSocket &operator=(const RawSocket &) = delete;

  void open_raw_socket(int *out_fd);
  void send_raw_packet(int sockfd, const uint8_t *packet, size_t packet_len);

private:
  int sockfd_;
};
