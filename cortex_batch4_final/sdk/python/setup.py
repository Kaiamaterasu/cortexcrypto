#!/usr/bin/env python3
"""
CortexCrypt Python SDK Setup
Copyright 2024 CortexCrypt Contributors
Licensed under Apache 2.0
"""

from setuptools import setup, Extension
import os
import subprocess
import sys

# Get version
VERSION = "1.0.0"

# Find CortexCrypt library
def find_cortexcrypt_lib():
    """Find CortexCrypt library and headers"""
    
    # Common search paths
    search_paths = [
        "/usr/local",
        "/usr",
        "../..",  # Build from source tree
        "../../build"
    ]
    
    for base_path in search_paths:
        include_path = os.path.join(base_path, "include")
        lib_path = os.path.join(base_path, "lib")
        
        header_file = os.path.join(include_path, "cortexcrypt.h")
        
        if os.path.exists(header_file):
            # Check for library file
            for lib_name in ["libcortexcrypt.so", "libcortexcrypt.a"]:
                lib_file = os.path.join(lib_path, lib_name)
                if os.path.exists(lib_file):
                    return include_path, lib_path
    
    # Try pkg-config
    try:
        include_dirs = subprocess.check_output(
            ["pkg-config", "--cflags-only-I", "cortexcrypt"],
            stderr=subprocess.DEVNULL
        ).decode().strip().split()
        
        lib_dirs = subprocess.check_output(
            ["pkg-config", "--libs-only-L", "cortexcrypt"],
            stderr=subprocess.DEVNULL
        ).decode().strip().split()
        
        if include_dirs and lib_dirs:
            include_path = include_dirs[0][2:]  # Remove -I prefix
            lib_path = lib_dirs[0][2:]  # Remove -L prefix
            return include_path, lib_path
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return None, None

# Build configuration
include_dir, lib_dir = find_cortexcrypt_lib()

if not include_dir or not lib_dir:
    print("ERROR: CortexCrypt library not found")
    print("Please install CortexCrypt or build it first:")
    print("  cd ../../ && make lib")
    sys.exit(1)

print(f"Found CortexCrypt library:")
print(f"  Include: {include_dir}")
print(f"  Library: {lib_dir}")

# C extension module
cortexcrypt_ext = Extension(
    'cortexcrypt._ffi',
    sources=['cortexcrypt/_ffi.c'],
    include_dirs=[include_dir],
    library_dirs=[lib_dir],
    libraries=['cortexcrypt'],
    extra_compile_args=['-std=c11', '-Wall', '-Wextra'],
)

# Long description
with open("../../README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cortexcrypt",
    version=VERSION,
    author="CortexCrypt Contributors", 
    author_email="dev@cortexcrypt.org",
    description="Zero-cost, offline, NN-augmented encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cortexcrypt/cortexcrypt",
    packages=["cortexcrypt"],
    ext_modules=[cortexcrypt_ext],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    keywords="cryptography encryption neural-networks security offline",
    project_urls={
        "Documentation": "https://github.com/cortexcrypt/cortexcrypt/blob/main/README.md",
        "Source": "https://github.com/cortexcrypt/cortexcrypt",
        "Tracker": "https://github.com/cortexcrypt/cortexcrypt/issues",
    },
    zip_safe=False,  # Due to C extension
)
