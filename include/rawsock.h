#ifndef RAWSOCK_H
#define RAWSOCK_H


/// @brief opens a raw socket on the specified interface
/// @param iface the name of the network interface
/// @return 
int open_raw_socket(const char *iface);


/// @brief return the index of the specified interface
/// @param sock 
/// @param iface 
/// @return 
int get_interface_index(int sock, const char *iface);

#endif // RAWSOCK_H