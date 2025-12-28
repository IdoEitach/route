#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <string>

// Function to send a packet to a specified IP and port
void send_packet(const std::string &packet_data, const std::string &dest_ip,
                 uint16_t dest_port);

// Function to calculate checksum of the packet data
unsigned short calculate_checksum(const std::string &data);

#endif // PACKET_H
