#include "../include/packet_batch.h"

PacketBatch::PacketBatch(unsigned int size, size_t max_packet_size)
    : batch_size(size), packets_received(0) {

  packets.resize(batch_size, std::vector<uint8_t>(max_packet_size));
  iov.resize(batch_size);
  msgs.resize(batch_size);
  memset(msgs.data(), 0, sizeof(mmsghdr) * batch_size);
  reset_for_recv(max_packet_size);
}

void PacketBatch::reset_for_recv(size_t max_packet_size) {
  packets_received = 0;
  for (size_t i = 0; i < batch_size; i++) {
    packets[i].resize(max_packet_size);
    iov[i].iov_base = packets[i].data();
    iov[i].iov_len = packets[i].size();
    msgs[i].msg_hdr.msg_iov = &iov[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }
}

void PacketBatch::prepare_for_send() {
  for (size_t i = 0; i < batch_size; i++) {
    iov[i].iov_len =
        msgs[i].msg_len; // Update iov length to the actual message length
  }
}
