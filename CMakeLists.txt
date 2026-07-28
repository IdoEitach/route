cmake_minimum_required(VERSION 3.15)

project(Route)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB SOURCES "src/*.cpp")

add_executable(main
    src/main.cpp 
    src/rawsock.cpp
    src/packet_batch.cpp
    src/packet_builder.cpp
    src/packet_detail.cpp
    src/hash_table.cpp
    src/forward.c         # Now this will actually compile!
    src/packet.c
)

include_directories(include)
