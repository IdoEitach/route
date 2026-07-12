#pragma once

#include <cstdint>
#include <cstring>
#include <sys/socket.h>
#include <vector>

class PacketBatch {
public:
  std::vector<std::vector<uint8_t>>
      packets; // vector of packets, each packet is a vector of bytes
  std::vector<iovec>
      iov; // vector of iovec structures for each packet, iov_base points to the
           // packet data, iov_len is the length of the packet
  std::vector<mmsghdr>
      msgs; // this is kinda useless in my case but the stuipd api requires it,
            // so we have to keep it around, each mmsghdr contains a msg_hdr
            // which has a pointer to the iovec and the length of the iovec
  unsigned int batch_size; // number of packets in the batch it will be the size
                           // of the packets vector, iov vector and msgs vector

  int packets_received; // number of packets received in the last batch, this is
                        // set by the recvmmsg call

  // Constructor declaration
  PacketBatch(unsigned int size, size_t max_packet_size = 65536);

  // Method declarations
  void reset_for_recv(size_t max_packet_size = 65536);
  void prepare_for_send(); // New method to handle private iov updates
};
