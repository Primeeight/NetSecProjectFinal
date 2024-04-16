cmake_minimum_required(VERSION 3.27)
project(NetSecProjectFinal)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)

add_executable(NetSecProjectFinal
        src/Client.cpp
        src/Client.h
        src/Main.cpp
        src/Main.h
        src/Server.cpp
        src/Server.h)
