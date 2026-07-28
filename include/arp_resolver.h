#include <iostream>
#include <sys/socket.h>
class ArpResolver {
public:
  bool lookup(uint32_t ip, MacAddress &mac);

  void resolve(uint32_t ip);

  void handle_arp_packet(Packet &p);

private:
  std::unordered_map<uint32_t, ArpEntry> cache;
  std::unordered_map<uint32_t, std::vector<Packet>> pending;
};
