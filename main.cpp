#include <iostream>
#include <stdlib.h>
#include "./include/packet_builder.h"
// #include "rawsock.h"
// #include "forward.h"
#include "hash_table.h"

int main() {
  
        // Example usage of hash table
    insert_ip_port(8080, "192.168.1.1");
    insert_ip_port(443, "192.168.1.1");


    print_table();
    remove_ip_port(8080);   

    print_table();
    const std::string src_ip = "10.100.102.3";
    const std::string dst_ip = "10.100.102.12";
    uint16_t src_port = 12345; 
    uint16_t dst_port = 80;
    const std::string payload = "Hello, UDP!";

    std::vector<uint8_t> packet = build_udp_packet(
        src_ip, dst_ip, src_port, dst_port, payload
    );

    std::cout << "Built UDP packet of size: " << packet.size() << " bytes" << std::endl;
    return 0;

    
}
    const std::string &dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    const std::string &payload
