#include "packet_builder.h"




uint16_t calculate_udp_checksum(const uint16_t* buf, int nwords) {
    
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++)
        sum += ntohs(buf[i]); // network byte order

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
                                          
    return htons(~sum);
}

std::vector<uint8_t> build_udp_packet(const std::string &src_ip,
    const std::string &dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    const std::string &payload)
{
    const int ip_header_len = 20;
    const int udp_header_len = 8;
    int total_len = ip_header_len + udp_header_len + payload.size();

    std::vector<uint8_t> packet(total_len, 0);

    // --- IP header ---
    iphdr *iph = (iphdr*)packet.data();
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    inet_pton(AF_INET, src_ip.c_str(), &iph->saddr);
    inet_pton(AF_INET, dst_ip.c_str(), &iph->daddr);
    iph->check = calculate_udp_checksum((uint16_t*)iph, ip_header_len / 2);
// we div it by 2 because there are 20 bytes at the ip header and each word is 2 bytes
// checksum is calculated over words 2 bytes
    // --- UDP header ---
    udphdr *udph = (udphdr*)(packet.data() + ip_header_len);
    udph->source = htons(src_port);
    udph->dest   = htons(dst_port);
    udph->len    = htons(udp_header_len + payload.size());
    udph->check  = 0; // optional for now

    // --- Payload ---
    memcpy(packet.data() + ip_header_len + udp_header_len,
           payload.data(), payload.size());

    return packet;                       
}
