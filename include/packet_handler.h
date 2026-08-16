#include "../include/packet_batch.h"
#include "../include/packet_builder.h"
#include "../include/packet_detail.h"
#include "../include/safe_queue.h"
#include <cstdint>
#include <functional>
#include <iostream>
#include <span>
#include <unordered_map>

// Context struct to pass resources to handlers if needed
struct PacketContext {
  SafeQueue<PacketBatch *> &to_send_queue;
  // ArpResolver &arp_resolver; // Add other dependencies as needed
};

// Function pointer / std::function signature for packet handlers
using PacketHandler =
    std::function<bool(std::span<uint8_t> packet, PacketContext &ctx)>;

// --- Handler Functions ---

bool handle_ipv4(std::span<uint8_t> packet, PacketContext &ctx);

bool handle_arp(std::span<uint8_t> packet, PacketContext &ctx);
