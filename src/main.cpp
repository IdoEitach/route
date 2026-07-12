#include "../include/packet_batch.h"
#include "../include/packet_builder.h"
#include "../include/rawsock.h"
#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
// #include "forward.h"
#include "../include/hash_table.h"
#include "../include/safe_queue.h"

void sniff_thread(RawSocket &sniffer_socket, const std::string &interface_name,
                  SafeQueue<PacketBatch *> &empty_queue,
                  SafeQueue<PacketBatch *> &to_process_queue) {
  while (true) {
    PacketBatch *batch = empty_queue.pop();
    int n = sniffer_socket.sniff_packets_batch(interface_name, *batch, 10000);
    if (n > 0) {
      to_process_queue.push(batch);
    } else {
      empty_queue.push(batch); // Return the batch to the empty queue if no
    }
  }
}

void process_thread(SafeQueue<PacketBatch *> &to_process_queue,
                    SafeQueue<PacketBatch *> &to_send_queue) {
  while (true) {
    PacketBatch packet_batch = nullptr;
    packet_batch = to_process_queue.pop();

    for (int i = 0; i < packet_batch.packets_received; ++i) {
      std::string src_mac, dst_mac, src_ip, dst_ip, payload;
      uint16_t src_port, dst_port;
      uint8_t protocol;

      try {
        get_packet_data(packet_batch.packets[i], src_mac, dst_mac, src_ip,
                        dst_ip, src_port, dst_port, payload, protocol);

        std::cout << "Src Mac: " << src_mac << ", Dst Mac: " << dst_mac
                  << std::endl;
        std::cout << "Src IP: " << src_ip << ", Dst IP: " << dst_ip
                  << ", Src Port: " << src_port << ", Dst Port: " << dst_port
                  << ", Protocol: " << (int)protocol << ", Payload: " << payload
                  << std::endl;
        to_send_queue.push(&packet_batch);

      } catch (const std::runtime_error &e) {
        std::cerr << "Runtime error processing packets: " << e.what()
                  << std::endl;

      } catch (const std::exception &e) {
        std::cerr << "Error processing packets: " << e.what() << std::endl;
      }
    }
  }
}

void send_thread(RawSocket &rawsocket, string &interface_name,
                 SafeQueue<PacketBatch> &to_send_queue,
                 SafeQueue<PacketBatch> &empty_queue) {
  while (true) {
    PacketBatch packet_batch(10);
    full_queue.pop(packet_batch);

    for (int i = 0; i < packet_batch.packets_received; ++i) {
      try {
        rawsocket.send_raw_packet(packet_batch.packets[i].data(),
                                  packet_batch.packets[i].size());
        std::cout << "Packet sent successfully!" << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "Error sending packet: " << e.what() << std::endl;
      }
    }
  }
}

int main() {

  const std::string src_ip = "10.100.102.21";
  const std::string dst_ip = "10.100.102.13";
  uint16_t src_port = 12345;
  uint16_t dst_port = 55555;
  constexpr unsigned int BATCH_SIZE = 10;
  constexpr unsigned int TIMEOUT_MS = 10000;
  std::vector<std::vector<uint8_t>> packet_batch;
  int packets_recieved_counter = 0;
  const std::string payload = "Hello, UDP!";

  std::string src_ip_sniff, dst_ip_sniff, payload_sniff;
  std::string src_mac_sniff, dst_mac_sniff;
  uint16_t src_port_sniff, dst_port_sniff;
  uint8_t protocol_sniff;

  SafeQueue<PacketBatch> empty_queue;
  SafeQueue<PacketBatch> full_queue;

  std::vector<uint8_t> packet =
      build_udp_packet(src_ip, src_port, dst_ip, dst_port, payload, 255);

  std::cout << "Built UDP packet of size: " << packet.size() << " bytes"
            << std::endl;
  try {
    print_packet(packet);
  } catch (std::invalid_argument &e) {
    std::cerr << "Error printing packet: " << e.what() << std::endl;
  }
  RawSocket raw_socket = RawSocket();

  try {

    raw_socket.open_raw_socket(AF_INET, IPPROTO_RAW);
    raw_socket.send_raw_packet(packet.data(), packet.size());

    std::cout << "Packet sent successfully!" << std::endl;
  } catch (const std::exception &e) {

    std::cerr << "Error sending packet: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  RawSocket sniffer_socket = RawSocket();
  std::string interface_name = "wlp1s0";
  std::vector<uint8_t> buffer(65536);

  try {
    sniffer_socket.ensure_socket(interface_name);
  } catch (const std::exception &e) {
    std::cerr << "Error ensuring socket: " << e.what() << std::endl;
  }
  for (int i = 0; i < 1000000000; i++) {

    int packets_received = sniffer_socket.sniff_packets_batch(
        interface_name, packet_batch, BATCH_SIZE, TIMEOUT_MS);

    packets_recieved_counter += packets_received;

    if (packets_received <= 0) {
      std::cout << "No packets received in the batch." << std::endl;
      return EXIT_SUCCESS;
    }
    for (int i = 0; i < packets_received; ++i) {
      try {
        get_packet_data(packet_batch[i], src_mac_sniff, dst_mac_sniff,
                        src_ip_sniff, dst_ip_sniff, src_port_sniff,
                        dst_port_sniff, payload_sniff, protocol_sniff);

        // std::cout << "Src Mac: " << src_mac_sniff
        //           << ", Dst Mac: " << dst_mac_sniff << std::endl;
        // std::cout << "Src IP: " << src_ip_sniff << ", Dst IP: " <<
        // dst_ip_sniff
        //           << ", Src Port: " << src_port_sniff
        //           << ", Dst Port: " << dst_port_sniff
        //           << ", Protocol: " << (int)protocol_sniff
        //           << ", Payload: " << payload_sniff << std::endl;

        src_ip_sniff.clear();
        dst_ip_sniff.clear();
        payload_sniff.clear();
        src_mac_sniff.clear();
        dst_mac_sniff.clear();
        src_port_sniff = 0;
        dst_port_sniff = 0;

      } catch (const std::runtime_error &e) {
        std::cerr << "Runtime error sniffing packets: " << e.what()
                  << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "Error sniffing packets: " << e.what() << std::endl;
      }
      std::cout << "Total packets received so far: " << packets_recieved_counter
                << std::endl;
    }
  }
  std::cout << "well its done" << std::endl;
  return 0;
}
