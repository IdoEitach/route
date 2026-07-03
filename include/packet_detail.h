#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

enum class FrameType { IPv4, ARP, VLAN, IPv6, Unknown };

void get_packet_data(const std::vector<uint8_t> &buffer, std::string &src_mac,
                     std::string &dst_mac, std::string &src_ip,
                     std::string &dst_ip, uint16_t &src_port,
                     uint16_t &dst_port, std::string &payload,
                     uint8_t &protocol);

void get_mac_address(const std::vector<uint8_t> &buffer,
                     std::string &src_mac_address,
                     std::string &dst_mac_address);

void get_ipv4_address(const uint8_t *buffer, std::string &src_str,
                      std::string &dst_str);

FrameType get_frame_type(const std::vector<uint8_t> &buffer);
