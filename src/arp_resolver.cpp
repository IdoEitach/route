#include "../include/arp_resolver.h"
#include <cstdint>

bool ArpResolver::lookup(uint32_t ip, MacAddress &mac) {
  if (!this->is_local_ip(ip)) {
    return false;
  }
  if (this->arp_cache_.contains(ip)) {
    mac = this->arp_cache_[ip].mac;
    return true;
  }

  // If not found, initiate ARP resolution
  if (this->resolve(ip)) {
    // After resolution, check again
    if (this->arp_cache_.contains(ip)) {
      mac = this->arp_cache_[ip].mac;
      return true;
    }
  }

  return false; // Resolution failed
}

bool ArpResolver::resolve(uint32_t ip) {
  // Send ARP request for the given IP
  // This is a placeholder; actual implementation would involve crafting and
  // sending an ARP request packet
  std::cout << "Resolving ARP for IP: " << ip << std::endl;

  if (pending_requests_.contains(ip)) {
    std::cout << "ARP request for IP " << ip << " is already pending."
              << std::endl;
    return false; // Already pending
  }

  if (arp_cache_.contains(ip)) {
    return true; // Already resolved
  }
  // we need to trigger arp request op code 1
}

void ArpResolver::handle_arp_reply(std::span<uint8_t> packet) {

  // Parse the ARP packet and update the ARP cache
  // This is a placeholder; actual implementation would involve parsing the
  // ARP packet and extracting the sender's IP and MAC address
  uint32_t sender_ip = 0;   // Extracted from ARP packet
  MacAddress sender_mac;    // Extracted from ARP packet
  if (packet.size() < 28) { // Minimum ARP packet size
    std::cerr << "Invalid ARP packet size." << std::endl;
    return;
  }
  // against arp spoofing.
  if (pending_requests_.contains(sender_ip) &&
      std::time(nullptr) - pending_requests_[sender_ip] < 5) {
    // Update the ARP cache
    this->arp_cache_[sender_ip] = {std::time(nullptr), sender_mac};
    pending_requests_.erase(sender_ip);
  }
}
