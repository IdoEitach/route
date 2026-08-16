#pragma once

#include <array>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unordered_map>
#include <vector>
// --- Custom MAC Address Type ---
struct MacAddress {
  std::array<uint8_t, 6> bytes{};

  // Modern C++20 comparison operators
  auto operator<=>(const MacAddress &) const = default;

  bool is_broadcast() const {
    for (uint8_t b : bytes) {
      if (b != 0xFF)
        return false;
    }
    return true;
  }

  std::string to_string() const {
    std::ostringstream ss;
    for (size_t i = 0; i < bytes.size(); ++i) {
      if (i > 0)
        ss << ":";
      ss << std::hex << std::setw(2) << std::setfill('0')
         << static_cast<int>(bytes[i]);
    }
    return ss.str();
  }
};

// --- ARP Cache Entry ---
struct ArpEntry {
  time_t last_updated;
  MacAddress mac;
  // You can add timestamps or state enums (e.g., REACHABLE, STALE) here later
};

struct PendingPacket {
  std::vector<uint8_t> packet_data;
  time_t timestamp;
};
// --- ARP Resolver ---
class ArpResolver {
public:
  ArpResolver(const std::string &interface_name, uint32_t net_mask = 0xFFFFFF00,
              uint32_t local_ip = 0x0A64661) {
    // Initialize the raw socket for ARP resolution
    netmask_ = net_mask;
    local_ip_ = local_ip;
  };
  bool is_local_ip(uint32_t ip) const {
    return (ip & netmask_) == (local_ip_ & netmask_);
  }
  bool lookup(uint32_t ip, MacAddress &mac);

  bool resolve(uint32_t ip);

  void handle_arp_reply(std::span<uint8_t> packet);

private:
  std::unordered_map<uint32_t, ArpEntry> arp_cache_;
  std::mutex mutex_;
  std::unordered_map<uint32_t, std::vector<PendingPacket>> pending_packets_;
  uint32_t netmask_; // Example netmask, adjust as needed
  uint32_t local_ip_;
  std::unordered_map<uint32_t, time_t> pending_requests_;
};
