#pragma once

#include "arp_resolver.h"
#include "packet_detail.h"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <span>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

void print_packet(const std::vector<uint8_t> &packet);
uint16_t calculate_ip_checksum(std::span<const uint8_t> buf, int len);

void build_arp_request(std::vector<uint8_t> &packet, const uint32_t &src_ip,
                       const uint32_t &dst_ip, const MacAddress &src_mac);
void build_arp_eth_layer(std::vector<uint8_t> &packet,
                         const MacAddress &src_mac);
void build_arp_request_packet_layer(std::span<uint8_t> packet,
                                    const uint32_t &src_ip,
                                    const uint32_t &dst_ip,
                                    const MacAddress &src_mac);

std::vector<uint8_t> build_udp_packet(const std::string &src_ip,
                                      uint16_t src_port,
                                      const std::string &dest_ip,
                                      uint16_t dest_port,
                                      const std::string &payload, uint8_t ttl);

void remove_ethernet_layer(std::vector<uint8_t> &packet);

void handle_ip4_layer(const std::vector<uint8_t> &packet, std::string &src_ip,
                      std::string &dst_ip);

void change_mac_addresses(std::span<uint8_t> buffer,
                          const MacAddress &new_src_mac,
                          const MacAddress &new_dst_mac);

void change_ipv4_addresses(std::span<uint8_t> buffer,
                           const uint32_t &new_src_ip,
                           const uint32_t &new_dst_ip);
