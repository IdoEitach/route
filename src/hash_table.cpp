#include "hash_table.h"
#include <iostream>

std::unordered_map<uint16_t, std::string> ip_port_map;

void insert_ip_port(uint16_t port, const std::string &ip) {
  ip_port_map[port] = ip;
}

void print_table() {
  std::cout << "Port-IP Hash Table Contents:\n";
  for (const auto &entry : ip_port_map) {
    std::cout << " Port: " << entry.first << " -> IP: " << entry.second << "\n";
  }
}

void remove_ip_port(uint16_t port) { ip_port_map.erase(port); }
