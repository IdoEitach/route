#ifndef PACKET_BUILDER_H
#define PACKET_BUILDER_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


std::vector<uint8_t> build_udp_packet(
    const std::string &src_ip,
    uint16_t src_port,
    const std::string &dest_ip,
    uint16_t dest_port,
    const std::string &payload
);

#endif // PACKET_BUILDER_H
