cmake_minimum_required(VERSION 3.19)
project(http_server)

set(CMAKE_CXX_STANDARD 17)

find_library(PTHREAD_LIBRARY pthread)
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Werror -pedantic")

add_executable(${PROJECT_NAME}
        http_server.cpp
        http_server.h
        main.cpp)

target_link_libraries(${PROJECT_NAME} ${PTHREAD_LIBRARY} OpenSSL::Crypto)