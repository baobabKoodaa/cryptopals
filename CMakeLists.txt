cmake_minimum_required(VERSION 3.10)
project(Cryptopals)

set(CMAKE_CXX_STANDARD 11)

add_executable(Cryptopals main.cpp set1.cpp set1.h aes.c aes.h aes.hpp)
#add_executable(Cryptopals aes.c aes.h aes.hpp test.cpp)