#include "packet_builder.h"




uint16_t calculate_checksum(const uint16_t* buf, int nwords) {
    
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++)
        sum += ntohs(buf[i]); // network byte order

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return htons(~sum);
}
