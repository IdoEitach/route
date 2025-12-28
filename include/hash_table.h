#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <cstdint>
#include <string>
#include <unordered_map>

// Hash Table for storing Port-IP pairs
extern std::unordered_map<uint16_t, std::string> ip_port_map;

// Function to insert Port-IP pair into the hash map
void insert_ip_port(uint16_t port, const std::string &ip);

// Function to print the contents of the hash table
void print_table();

void remove_ip_port(uint16_t port);

#endif // HASH_TABLE_H
