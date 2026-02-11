cmake_minimum_required(VERSION 3.15)
project(LamarckFUSE C)

# LamarckFUSE — NFSv4 loopback FUSE for Windows (Pro/Enterprise)
# Adapted from DarwinFUSE for cross-platform use.
#
# Usage:
#   cd LamarckFUSE
#   cmake -B build
#   cmake --build build
#
# Produces: lamarckfuse.lib (static library)

set(CMAKE_C_STANDARD 11)

# Source files
set(LAMARCKFUSE_SOURCES
    src/lamarckfuse.c
    src/nfs4_server.c
    src/nfs4_ops.c
    src/nfs4_xdr.c
    src/rpc.c
)

# Header files (for IDE project display)
set(LAMARCKFUSE_HEADERS
    include/fuse.h
    src/platform_compat.h
    src/lamarckfuse_internal.h
    src/nfs4_server.h
    src/nfs4_ops.h
    src/nfs4_xdr.h
    src/rpc.h
    src/fuse_context.h
)

# Static library
add_library(lamarckfuse STATIC ${LAMARCKFUSE_SOURCES} ${LAMARCKFUSE_HEADERS})

# Include paths
target_include_directories(lamarckfuse
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Platform-specific configuration
if(WIN32)
    target_link_libraries(lamarckfuse PRIVATE
        ws2_32      # Winsock2
        bcrypt      # BCryptGenRandom
        mpr         # WNetAddConnection2 / WNetCancelConnection2
    )
    target_compile_definitions(lamarckfuse PRIVATE
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )
else()
    # POSIX (macOS / Linux)
    target_compile_options(lamarckfuse PRIVATE -Wall -Wextra -Wpedantic)
    find_package(Threads REQUIRED)
    target_link_libraries(lamarckfuse PRIVATE Threads::Threads)
endif()
