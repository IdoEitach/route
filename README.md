# route
This project is meant to send packets and change the ip of the src ip and mac.
great to use after a successful spoofing.


this is very important to run with root privileges.

the build of IP packet:
```cpp 
// IPv4 header = 20 bytes (IHL=5)
buffer[0]  = 0x45; // Version=4, IHL=5 (20 bytes)
buffer[1]  = 0x00; // DSCP/ECN (Type of Service)

buffer[2]  = 0x00; // Total Length (high byte)
buffer[3]  = 0x14; // Total Length (low byte) = 20 if header-only

buffer[4]  = 0x00; // Identification (high)
buffer[5]  = 0x01; // Identification (low)

buffer[6]  = 0x40; // Flags+FragOffset (high): 0x40 => DF set, offset=0
buffer[7]  = 0x00; // Flags+FragOffset (low)

buffer[8]  = 0x40; // TTL (64)
buffer[9]  = 0x11; // Protocol (17=UDP). Use 0x06 for TCP, 0x01 for ICMP.

buffer[10] = 0x00; // Header checksum (high) -> compute later
buffer[11] = 0x00; // Header checksum (low)

buffer[12] = 192;  // Source IP byte 1
buffer[13] = 168;  // Source IP byte 2
buffer[14] = 1;    // Source IP byte 3
buffer[15] = 10;   // Source IP byte 4

buffer[16] = 192;  // Dest IP byte 1
buffer[17] = 168;  // Dest IP byte 2
buffer[18] = 1;    // Dest IP byte 3
buffer[19] = 20;   // Dest IP byte 4
```
