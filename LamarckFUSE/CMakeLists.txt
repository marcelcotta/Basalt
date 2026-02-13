cmake_minimum_required(VERSION 3.15)
project(LamarckFUSE C)

# LamarckFUSE — Windows-only FUSE for Basalt
#
# Uses iSCSI target (127.0.0.1:3260) for block-level access.
# The Windows iSCSI Initiator creates a real local block device.
#
# On macOS/Linux, DarwinFUSE is used instead (separate directory).
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
    src/iscsi_target.c
    src/iscsi_pdu.c
    src/iscsi_scsi.c
)

# Header files (for IDE project display)
set(LAMARCKFUSE_HEADERS
    include/fuse.h
    src/platform_compat.h
    src/lamarckfuse_internal.h
    src/fuse_context.h
    src/iscsi_target.h
    src/iscsi_pdu.h
    src/iscsi_scsi.h
)

# Static library
add_library(lamarckfuse STATIC ${LAMARCKFUSE_SOURCES} ${LAMARCKFUSE_HEADERS})

# Include paths
target_include_directories(lamarckfuse
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Windows configuration
target_link_libraries(lamarckfuse PRIVATE
    ws2_32      # Winsock2
    bcrypt      # BCryptGenRandom
)
target_compile_definitions(lamarckfuse PRIVATE
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)
