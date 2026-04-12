cmake_minimum_required(VERSION 3.16)
project(libcortexcrypt VERSION 1.0.0 LANGUAGES C)

# Build configuration
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(ARGON2 REQUIRED libargon2)
pkg_check_modules(BLKID REQUIRED blkid)

# Find ONNX Runtime
find_path(ONNXRUNTIME_INCLUDE_DIR onnxruntime_c_api.h 
    PATHS /usr/local/include /usr/include
    PATH_SUFFIXES onnxruntime/core/session)
find_library(ONNXRUNTIME_LIB onnxruntime 
    PATHS /usr/local/lib /usr/lib)

if(NOT ONNXRUNTIME_INCLUDE_DIR OR NOT ONNXRUNTIME_LIB)
    message(STATUS "ONNX Runtime not found, will build minimal fallback")
    set(USE_ONNX_RUNTIME OFF)
else()
    message(STATUS "Found ONNX Runtime: ${ONNXRUNTIME_LIB}")
    set(USE_ONNX_RUNTIME ON)
endif()

# Source files
set(SOURCES
    src/cortexcrypt.c
    src/format.c
    src/crypto.c
    src/binding.c
    src/daemon_client.c
    src/neural.c
    src/utils.c
)

# Create shared library
add_library(cortexcrypt SHARED ${SOURCES})

# Include directories
target_include_directories(cortexcrypt 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${OPENSSL_INCLUDE_DIRS}
        ${ARGON2_INCLUDE_DIRS}
        ${BLKID_INCLUDE_DIRS}
)

if(USE_ONNX_RUNTIME)
    target_include_directories(cortexcrypt PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
    target_compile_definitions(cortexcrypt PRIVATE USE_ONNX_RUNTIME=1)
endif()

# Link libraries
target_link_libraries(cortexcrypt 
    ${OPENSSL_LIBRARIES}
    ${ARGON2_LIBRARIES}
    ${BLKID_LIBRARIES}
    pthread
    m
)

if(USE_ONNX_RUNTIME)
    target_link_libraries(cortexcrypt ${ONNXRUNTIME_LIB})
endif()

# Compiler flags
target_compile_options(cortexcrypt PRIVATE ${OPENSSL_CFLAGS_OTHER} ${ARGON2_CFLAGS_OTHER} ${BLKID_CFLAGS_OTHER})

# Library properties
set_target_properties(cortexcrypt PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER include/cortexcrypt.h
)

# Install rules
install(TARGETS cortexcrypt
    EXPORT cortexcryptTargets
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

install(EXPORT cortexcryptTargets
    FILE cortexcryptTargets.cmake
    DESTINATION lib/cmake/cortexcrypt
)

# Generate package config
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    cortexcryptConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cortexcryptConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cortexcryptConfig.cmake"
    INSTALL_DESTINATION lib/cmake/cortexcrypt
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/cortexcryptConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/cortexcryptConfigVersion.cmake"
    DESTINATION lib/cmake/cortexcrypt
)
