#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string>
#include <unistd.h>
#include <vector>

void print_packet(const std::vector<uint8_t> &packet);

std::vector<uint8_t> build_udp_packet(const std::string &src_ip,
                                      uint16_t src_port,
                                      const std::string &dest_ip,
                                      uint16_t dest_port,
                                      const std::string &payload, uint8_t ttl);

void get_packet_data(const std::vector<uint8_t> &buffer, std::string &src_ip,
                     std::string &dst_ip, uint16_t &src_port,
                     uint16_t &dst_port, std::string &payload,
                     uint8_t &protocol);
