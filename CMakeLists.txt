cmake_minimum_required(VERSION 3.26)
project(Janus)

set(CMAKE_CXX_STANDARD 17)

add_executable(Janus main.cpp)
add_executable(client client.cpp)
target_link_libraries(Janus PRIVATE ws2_32.lib)
target_link_libraries(client PRIVATE ws2_32.lib)