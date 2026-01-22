cmake_minimum_required(VERSION 3.16)
project(darkelf_pq_mini_engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- OpenSSL ---
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# --- liboqs ---
# Try to find the library and the header.
# Users can hint with:
#   -DOQS_ROOT=/path/to/liboqs/install
# or with CMAKE_PREFIX_PATH.
set(OQS_ROOT "" CACHE PATH "Prefix path to liboqs installation (optional)")

if (OQS_ROOT)
  list(APPEND CMAKE_PREFIX_PATH "${OQS_ROOT}")
  list(APPEND CMAKE_LIBRARY_PATH "${OQS_ROOT}/lib" "${OQS_ROOT}/lib64")
  list(APPEND CMAKE_INCLUDE_PATH "${OQS_ROOT}/include")
endif()

find_path(OQS_INCLUDE_DIR
  NAMES oqs/oqs.h
  HINTS ${CMAKE_INCLUDE_PATH}
)

find_library(OQS_LIBRARY
  NAMES oqs liboqs
  HINTS ${CMAKE_LIBRARY_PATH}
)

if (NOT OQS_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find oqs/oqs.h. Install liboqs or set -DOQS_ROOT=/path/to/install")
endif()

if (NOT OQS_LIBRARY)
  message(FATAL_ERROR "Could not find liboqs library. Install liboqs or set -DOQS_ROOT=/path/to/install")
endif()

message(STATUS "Found liboqs include: ${OQS_INCLUDE_DIR}")
message(STATUS "Found liboqs library: ${OQS_LIBRARY}")

# --- Library target ---
add_library(pqme
  src/engine.cpp
  src/framing.cpp
  src/util.cpp
  src/transport_tcp_posix.cpp
  src/transport_socks5.cpp
)

target_include_directories(pqme
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OQS_INCLUDE_DIR}
)

target_link_libraries(pqme
  PUBLIC
    OpenSSL::Crypto
    ${OQS_LIBRARY}
)

# Helpful compile warnings (optional but good)
if (MSVC)
  target_compile_options(pqme PRIVATE /W4)
else()
  target_compile_options(pqme PRIVATE -Wall -Wextra -Wpedantic)
endif()

# --- Apps ---
add_executable(pqme-keygen apps/pqme-keygen.cpp)
target_link_libraries(pqme-keygen PRIVATE pqme)

add_executable(pqme-server apps/pqme-server.cpp)
target_link_libraries(pqme-server PRIVATE pqme)

add_executable(pqme-client apps/pqme-client.cpp)
target_link_libraries(pqme-client PRIVATE pqme)

Example

cmake -S . -B build -DOQS_ROOT=/opt/liboqs
cmake --build build -j

