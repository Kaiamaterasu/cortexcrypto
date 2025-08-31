cmake_minimum_required(VERSION 3.16)
project(cortexcrypt-cli VERSION 1.0.0 LANGUAGES C)

# Build configuration
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find CortexCrypt library
find_path(CORTEXCRYPT_INCLUDE_DIR cortexcrypt.h
    PATHS ../lib/include ../build/lib/include /usr/local/include)
find_library(CORTEXCRYPT_LIB cortexcrypt
    PATHS ../build/lib /usr/local/lib)

if(NOT CORTEXCRYPT_INCLUDE_DIR OR NOT CORTEXCRYPT_LIB)
    message(FATAL_ERROR "CortexCrypt library not found. Build lib/ first.")
endif()

# Source files
set(SOURCES src/main.c)

# Create CLI executable
add_executable(cortexcrypt ${SOURCES})

# Include directories
target_include_directories(cortexcrypt PRIVATE ${CORTEXCRYPT_INCLUDE_DIR})

# Link libraries
target_link_libraries(cortexcrypt ${CORTEXCRYPT_LIB})

# Create cortexctl symlink target
add_custom_target(cortexctl ALL
    COMMAND ${CMAKE_COMMAND} -E create_symlink cortexcrypt cortexctl
    DEPENDS cortexcrypt
    COMMENT "Creating cortexctl symlink"
)

# Install rules
install(TARGETS cortexcrypt DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cortexctl DESTINATION bin)
