cmake_minimum_required(VERSION 3.10)

# Project name
project(reslirp)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
pkg_search_module(SLIRP REQUIRED slirp)

# Include directories
include_directories(${GLIB_INCLUDE_DIRS} ${SLIRP_INCLUDE_DIRS})

# Link directories
link_directories(${SLIRP_LIBRARY_DIRS})

# Add the executable
add_executable(reslirp
    src/appdump.cpp
    src/ipdump.cpp
    src/main.cpp
    src/moreethdump.cpp
    src/moreipdump.cpp
    src/pktdump.cpp
    src/reslirp.cpp
    src/utildump.cpp
)

# Link libraries
target_link_libraries(reslirp ${GLIB_LIBRARIES} ${SLIRP_LIBRARIES})

# Set the output directory for the executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
