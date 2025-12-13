#include <iostream>
#include <stdio.h>
#include <stdlib.h>
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
    return 0;

    
}

