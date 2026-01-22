cmake_minimum_required(VERSION 3.16)
project(darkelf_pq_mini_engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_library(OQS_LIB oqs REQUIRED)

add_library(pqme
  src/engine.cpp
  src/framing.cpp
  src/util.cpp
  src/transport_tcp_posix.cpp
  src/transport_socks5.cpp
)
target_include_directories(pqme PUBLIC include)
target_link_libraries(pqme PUBLIC OpenSSL::Crypto ${OQS_LIB})

add_executable(pqme-keygen apps/pqme-keygen.cpp)
target_link_libraries(pqme-keygen PRIVATE pqme)

add_executable(pqme-server apps/pqme-server.cpp)
target_link_libraries(pqme-server PRIVATE pqme)

add_executable(pqme-client apps/pqme-client.cpp)
target_link_libraries(pqme-client PRIVATE pqme)
