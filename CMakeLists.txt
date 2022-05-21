cmake_minimum_required(VERSION 3.20)
# set(CMAKE_TOOLCHAIN_FILE "/home/lighthouse/sources/vcpkg/scripts/buildsystems/vcpkg.cmake")
project(net-capture)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS True)

find_package(fmt REQUIRED)

add_library(netcap INTERFACE)
target_include_directories(netcap INTERFACE include)
target_compile_options(netcap INTERFACE -Wall -Wextra -pedantic)
target_link_libraries(netcap INTERFACE fmt::fmt)

add_subdirectory(job)
