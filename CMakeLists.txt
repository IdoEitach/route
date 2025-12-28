cmake_minimum_required(VERSION 3.15)

project(Route)

set(CMAKE_CXX_STANDARD 17)

file(GLOB SOURCES "src/*.cpp")

add_executable(main ${SOURCES})

include_directories(include)
