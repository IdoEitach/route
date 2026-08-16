#include "../include/packet_batch.h"
#include "../include/packet_builder.h"
#include "../include/packet_handler.h"
#include "../include/rawsock.h"
#include <cstdint>
#include <iostream>
#include <iterator>
#include <stdlib.h>
#include <sys/socket.h>
// #include "forward.h"
#include "../include/hash_table.h"
#include "../include/safe_queue.h"
#include <span>
#include <thread>

/// <summary>
/// This function is for sniffing packets in a batch.
/// it will pop a packet batch from the empty_queue, sniff packets into it, and
/// then push it to the to_process_queue It will sniff packets from the
/// specified interface and push the packet batch to the to_process_queue.
/// </summary>
/// <param name="sniffer_socket">The raw socket to sniff packets from.</param>
/// <param name="interface_name">The name of the interface to sniff packets
/// from.</param> <param name="empty_queue">The queue of empty packet batches to
/// use for sniffing.</ param name="to_process_queue">The queue of packet
/// batches to process after sniffing.</param>
void sniff_thread(RawSocket &sniffer_socket, const std::string &interface_name,
                  SafeQueue<PacketBatch *> &empty_queue,
                  SafeQueue<PacketBatch *> &to_process_queue) {
  while (true) {
    PacketBatch *batch = empty_queue.pop();
    int n = sniffer_socket.sniff_packets_batch(interface_name, *batch, 10000);
    if (n > 0) { // if we got messages
      to_process_queue.push(batch);
    } else { // if we havegot no messages
      batch->reset_for_recv(65536);
      empty_queue.push(batch); // Return the batch to the empty queue if no
    }
  }
}

/// This function is for processing packets in a batch. It takes a queue of
/// packets to process and a queue of packets to send. It will process each
/// chagne the ips SafeQueue<PacketBatch *> &to_process_queue pointers to the
/// packet batch that currntly need to process. SafeQueue<PacketBatch *>
/// &to_send_queue pointers to the packet batch that are ready to send.
void process_thread(SafeQueue<PacketBatch *> &to_process_queue,
                    SafeQueue<PacketBatch *> &to_send_queue) {

  PacketContext ctx{to_send_queue};

  static const std::unordered_map<FrameType, PacketHandler> dispatch_table = {
      {FrameType::IPv4, handle_ipv4}, {FrameType::ARP, handle_arp}};

  while (true) {
    PacketBatch *packet_batch = nullptr;
    packet_batch = to_process_queue.pop();
    int write_index = 0;
    for (int i = 0; i < (*packet_batch).packets_received; ++i) {
      try {
        FrameType frmae_type = get_frame_type(packet_batch->packets[i]);

        auto handler_it = dispatch_table.find(frmae_type);
        if (handler_it != dispatch_table.end()) {
          bool keep_packet =
              handler_it->second((*packet_batch).packets[i], ctx);
          if (keep_packet) {
            if (write_index != i) {
              packet_batch->packets[write_index] =
                  std::move(packet_batch->packets[i]);
            }
            packet_batch->msgs[write_index].msg_len =
                packet_batch->msgs[i].msg_len;
            ++write_index;
          }
        } else {
          std::cerr << "No handler for frame type: "
                    << static_cast<int>(frmae_type) << std::endl;
        }

      } catch (const std::exception &e) {
        std::cerr << "Error processing packet: " << e.what() << std::endl;
      }
    }

    packet_batch->packets_received = write_index;

    to_send_queue.push(packet_batch);
  }
}

/// <summary>
/// This function is for sending packets in a batch.
/// It consume from the to_send_queue and send packets and than return the
/// batch to the empty_queue.
/// </summary>
/// <param>
/// <param name="rawsocket">The raw socket to send packets through.</param>
/// <param name="interface_name">The name of the interface to send packets
/// through.
/// <param name="to_send_queue">The queue of packets to send.</param>
/// <param name="empty_queue">The queue of empty packet batches to return
/// to_send_queue after sending.
/// </param>
// comment: This function will use later version send packet batch with
// sendmmsg() to send multiple packets in one system call.
void send_thread(RawSocket &rawsocket, const std::string &interface_name,
                 SafeQueue<PacketBatch *> &to_send_queue,
                 SafeQueue<PacketBatch *> &empty_queue) {

  while (true) {
    PacketBatch *packet_batch = nullptr;
    packet_batch = to_send_queue.pop();
    if (packet_batch == nullptr) {
      std::cerr << "Error: Received a null packet batch from to_send_queue."
                << std::endl;
      continue; // Skip this iteration and wait for the next batch
    }
    packet_batch->prepare_for_send(); // Prepare the packet batch for sending
    if ((*packet_batch).packets_received > 0) {
      for (int i = 0; i < (*packet_batch).packets_received; ++i) {
        try {
          std::cout << "Sending packet of size: "
                    << packet_batch->msgs[i].msg_len << std::endl;
          rawsocket.send_raw_packet((*packet_batch).packets[i].data(),
                                    packet_batch->msgs[i].msg_len,
                                    interface_name);
          // std::cout << "Packet sent successfully!" << std::endl;
        } catch (const std::exception &e) {
          std::cerr << "Error sending packet: " << e.what() << std::endl;
          std::cerr << "Packet size: " << packet_batch->msgs[i].msg_len
                    << std::endl;
          std::cerr << "Packet data: ";
          for (size_t j = 0; j < packet_batch->msgs[i].msg_len; ++j) {
            std::cerr << std::hex
                      << static_cast<int>(packet_batch->packets[i][j]) << " ";
          }
          std::cerr << std::dec << std::endl; // Reset to decimal output
        }
        // Return the packet batch to the empty
        // queue for reuse
      }
    }

    packet_batch->reset_for_recv(65536); // Reset the packet batch for receiving
    empty_queue.push(packet_batch);
  }
}

int main() {

  const std::string src_ip = "10.100.102.21";
  const std::string dst_ip = "10.100.102.13";
  std::string interface_name = "wlp1s0";
  uint16_t src_port = 12345;
  uint16_t dst_port = 55555;
  constexpr unsigned int BATCH_SIZE = 10;
  constexpr unsigned int TIMEOUT_MS = 1000;
  std::vector<std::vector<uint8_t>> packet_batch;
  int packets_recieved_counter = 0;
  RawSocket sniffer_socket;
  RawSocket sender_socket;
  int batch_size = 10;
  int batch_count = 4;

  sender_socket.open_raw_socket(AF_PACKET, htons(ETH_P_ALL));
  std::cout << "the sedner socket fd" << sender_socket.sockfd_ << std::endl;

  SafeQueue<PacketBatch *> empty_queue;
  SafeQueue<PacketBatch *> full_queue;
  SafeQueue<PacketBatch *> to_send_queue;

  std::vector<std::unique_ptr<PacketBatch>> batch_pool;

  for (int i = 0; i < batch_count; i++) {
    auto batch = std::make_unique<PacketBatch>(batch_size);
    batch->reset_for_recv(65536);

    empty_queue.push(batch.get());
    batch_pool.push_back(std::move(batch));
  }

  std::thread sniffing_thread(sniff_thread, std::ref(sniffer_socket),
                              std::ref(interface_name), std::ref(empty_queue),
                              std::ref(full_queue));

  std::thread processing_thread(process_thread, std::ref(full_queue),
                                std::ref(to_send_queue));

  std::thread sending_thread(send_thread, std::ref(sender_socket),
                             std::ref(interface_name), std::ref(to_send_queue),
                             std::ref(empty_queue));
  sniffing_thread.join();
  processing_thread.join();
  sending_thread.join();
  return 0;
}
