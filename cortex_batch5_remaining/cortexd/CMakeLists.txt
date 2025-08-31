cmake_minimum_required(VERSION 3.16)
project(cortexd VERSION 1.0.0 LANGUAGES C)

# Build configuration
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find dependencies
find_package(PkgConfig REQUIRED)

# Source files
set(SOURCES
    src/main.c
    src/daemon.c
    src/telemetry.c
)

# Create executable
add_executable(cortexd ${SOURCES})

# Include directories
target_include_directories(cortexd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/src
)

# Link libraries
target_link_libraries(cortexd 
    pthread
    m
    ${CMAKE_CURRENT_SOURCE_DIR}/../build/lib/libcortexcrypt.so
)

# Install rules
install(TARGETS cortexd
    RUNTIME DESTINATION bin
)

install(FILES systemd/cortexd.service
    DESTINATION lib/systemd/system
)
