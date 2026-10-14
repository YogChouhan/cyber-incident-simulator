cmake_minimum_required(VERSION 3.10)

# Project Definition
project(CyberIncidentSimulator
    VERSION 1.0.0
    DESCRIPTION "Cyber Incident Response Simulator for Object Oriented Programming"
    LANGUAGES CXX
)

# Standard C++17 Enforcement
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include Header Directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source Files
set(SOURCES
    src/main.cpp
    src/Device.cpp
    src/Incident.cpp
    src/Simulator.cpp
)

# Executable Target
add_executable(CyberIncidentSimulator ${SOURCES})

# Compiler Warnings and Flags for MinGW GCC / Clang
if(MSVC)
    target_compile_options(CyberIncidentSimulator PRIVATE /W4 /permissive-)
else()
    target_compile_options(CyberIncidentSimulator PRIVATE -Wall -Wextra -pedantic)
endif()
