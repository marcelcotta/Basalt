#!/bin/bash
#
# Build universal (arm64 + x86_64) binaries for Basalt (macOS)
# Produces: libBasaltCore.a, basalt-cli, Basalt.app
#
# Usage: ./build-universal.sh [release|debug]
#

set -e

BUILD_CONFIG="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# Symlink for spaces-in-path workaround
SYMLINK="/tmp/truecrypt-build"
ln -sfn "${SCRIPT_DIR}" "${SYMLINK}"

BUILD_ROOT="${SYMLINK}/build-universal"
ARM64_DIR="${BUILD_ROOT}/arm64"
X86_64_DIR="${BUILD_ROOT}/x86_64"
OUTPUT_DIR="${BUILD_ROOT}/universal"

echo "============================================"
echo "  Basalt Universal Binary Build"
echo "  Config: ${BUILD_CONFIG}"
echo "============================================"
echo ""

# Clean previous universal build
rm -rf "${BUILD_ROOT}"
mkdir -p "${ARM64_DIR}" "${X86_64_DIR}" "${OUTPUT_DIR}"

# ============================================================
# Helper: build libBasaltCore.a for a specific architecture
# ============================================================
build_core_lib() {
    local ARCH="$1"
    local OUT_DIR="$2"

    echo ""
    echo "=== Building libBasaltCore.a (${ARCH}) ==="
    echo ""

    # Clean object files from previous build
    for DIR in Platform Volume Fuse Core; do
        rm -f "${SYMLINK}/src/${DIR}/${DIR}.a"
        find "${SYMLINK}/src/${DIR}" -name '*.o' -delete 2>/dev/null || true
    done
    # Also clean Crypto and Common .o files (they live outside Volume/)
    find "${SYMLINK}/src/Crypto" -name '*.o' -delete 2>/dev/null || true
    find "${SYMLINK}/src/Common" -name '*.o' -delete 2>/dev/null || true
    rm -f "${SYMLINK}/libBasaltCore.a"

    # Build with architecture override
    # TARGET_ARCH controls which arch-specific crypto sources are included
    make -C "${SYMLINK}" BASE_DIR="${SYMLINK}" NOASM=1 \
        TARGET_ARCH="${ARCH}" \
        TC_EXTRA_CFLAGS="-arch ${ARCH}" \
        TC_EXTRA_CXXFLAGS="-arch ${ARCH}" \
        TC_EXTRA_LFLAGS="-arch ${ARCH}" \
        libBasaltCore

    # Verify architecture
    echo "  Verifying ${ARCH}..."
    lipo -info "${SYMLINK}/libBasaltCore.a" 2>/dev/null || true

    # Copy to output
    cp "${SYMLINK}/libBasaltCore.a" "${OUT_DIR}/libBasaltCore.a"
}

# ============================================================
# Helper: build CLI for a specific architecture
# ============================================================
build_cli() {
    local ARCH="$1"
    local OUT_DIR="$2"

    echo ""
    echo "=== Building basalt-cli (${ARCH}) ==="
    echo ""

    # Clean CLI objects
    rm -f "${SYMLINK}/CLI/"*.o "${SYMLINK}/CLI/basalt-cli"

    make -C "${SYMLINK}" BASE_DIR="${SYMLINK}" NOASM=1 NOTEST=1 \
        TARGET_ARCH="${ARCH}" \
        TC_EXTRA_CFLAGS="-arch ${ARCH}" \
        TC_EXTRA_CXXFLAGS="-arch ${ARCH}" \
        TC_EXTRA_LFLAGS="-arch ${ARCH}" \
        cli

    cp "${SYMLINK}/CLI/basalt-cli" "${OUT_DIR}/basalt-cli"
}

# ============================================================
# Helper: build SwiftUI app for a specific architecture
# ============================================================
build_swiftui() {
    local ARCH="$1"
    local OUT_DIR="$2"
    local CORE_LIB="${OUT_DIR}/libBasaltCore.a"

    echo ""
    echo "=== Building Basalt (${ARCH}) ==="
    echo ""

    local SDK_PATH
    SDK_PATH="$(xcrun --show-sdk-path)"
    local MIN_MACOS="12.0"
    local BRIDGE_DIR="${SYMLINK}/Basalt/Bridge"
    local APP_DIR="${SYMLINK}/Basalt/App"
    local OBJ_DIR="${OUT_DIR}/obj"
    mkdir -p "${OBJ_DIR}"

    # Compiler flags
    local COMMON_FLAGS="-arch ${ARCH} -mmacosx-version-min=${MIN_MACOS} -isysroot ${SDK_PATH}"
    local CXX_FLAGS="${COMMON_FLAGS} -std=c++14 -stdlib=libc++ -I${SYMLINK}/src -I${SYMLINK}/src/Crypto"
    CXX_FLAGS="${CXX_FLAGS} -DTC_UNIX -DTC_BSD -DTC_MACOSX -D__STDC_WANT_LIB_EXT1__=1"
    CXX_FLAGS="${CXX_FLAGS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES"
    local OBJCXX_FLAGS="${CXX_FLAGS} -fobjc-arc -Wno-potentially-evaluated-expression"

    if [ "${BUILD_CONFIG}" = "release" ]; then
        OBJCXX_FLAGS="${OBJCXX_FLAGS} -O2"
        local SWIFT_FLAGS="-O"
    else
        OBJCXX_FLAGS="${OBJCXX_FLAGS} -DDEBUG -g"
        local SWIFT_FLAGS="-Onone -g"
    fi

    # Compile ObjC++ Bridge
    echo "  Compiling Bridge (${ARCH})..."
    for src in "${BRIDGE_DIR}"/*.mm; do
        base="$(basename "${src}" .mm)"
        echo "    ${base}.mm"
        clang++ ${OBJCXX_FLAGS} -c "${src}" -o "${OBJ_DIR}/${base}.o"
    done

    # Compile Swift
    echo "  Compiling Swift (${ARCH})..."
    local SWIFT_SOURCES
    SWIFT_SOURCES=$(find "${APP_DIR}" -name "*.swift" -type f | sort)
    local BRIDGING_HEADER="${BRIDGE_DIR}/Basalt-Bridging-Header.h"

    # Generate output-file-map
    local OUTPUT_FILE_MAP="${OBJ_DIR}/output-file-map.json"
    echo "{" > "${OUTPUT_FILE_MAP}"
    local FIRST=1
    for src in ${SWIFT_SOURCES}; do
        base="$(basename "${src}" .swift)"
        obj="${OBJ_DIR}/${base}.swift.o"
        if [ ${FIRST} -eq 0 ]; then echo "," >> "${OUTPUT_FILE_MAP}"; fi
        FIRST=0
        printf '  "%s": { "object": "%s" }' "${src}" "${obj}" >> "${OUTPUT_FILE_MAP}"
    done
    echo "" >> "${OUTPUT_FILE_MAP}"
    echo "}" >> "${OUTPUT_FILE_MAP}"

    swiftc \
        ${SWIFT_FLAGS} \
        -target "${ARCH}-apple-macosx${MIN_MACOS}" \
        -sdk "${SDK_PATH}" \
        -import-objc-header "${BRIDGING_HEADER}" \
        -module-name Basalt \
        -emit-module -emit-module-path "${OBJ_DIR}/Basalt.swiftmodule" \
        -emit-object \
        -parse-as-library \
        -output-file-map "${OUTPUT_FILE_MAP}" \
        ${SWIFT_SOURCES}

    # Link
    echo "  Linking (${ARCH})..."
    local LINK_FLAGS="-arch ${ARCH} -mmacosx-version-min=${MIN_MACOS} -isysroot ${SDK_PATH}"
    LINK_FLAGS="${LINK_FLAGS} -stdlib=libc++ -Wl,-dead_strip"

    local SWIFT_LIB_DIR
    SWIFT_LIB_DIR="$(dirname "$(xcrun --find swiftc)")/../lib/swift/macosx"

    local FUSE_LIBS="${SYMLINK}/src/DarwinFUSE/libdarwinfuse.a"

    local SWIFT_OBJS
    SWIFT_OBJS=$(find "${OBJ_DIR}" -name "*.swift.o" -type f | sort)

    clang++ ${LINK_FLAGS} \
        "${OBJ_DIR}"/TCCoreBridge.o \
        "${OBJ_DIR}"/TCCocoaCallback.o \
        ${SWIFT_OBJS} \
        "${CORE_LIB}" \
        ${FUSE_LIBS} \
        -framework AppKit \
        -framework Security \
        -framework SwiftUI \
        -framework Combine \
        -L "${SWIFT_LIB_DIR}" \
        -Wl,-rpath,/usr/lib/swift \
        -o "${OUT_DIR}/Basalt"
}

# ============================================================
# Step 1: Build for arm64
# ============================================================
build_core_lib "arm64" "${ARM64_DIR}"
build_cli "arm64" "${ARM64_DIR}"
build_swiftui "arm64" "${ARM64_DIR}"

# ============================================================
# Step 2: Build for x86_64
# ============================================================
build_core_lib "x86_64" "${X86_64_DIR}"
build_cli "x86_64" "${X86_64_DIR}"
build_swiftui "x86_64" "${X86_64_DIR}"

# ============================================================
# Step 3: Create universal binaries with lipo
# ============================================================
echo ""
echo "=== Creating Universal Binaries ==="
echo ""

# libBasaltCore.a
echo "  libBasaltCore.a..."
lipo -create \
    "${ARM64_DIR}/libBasaltCore.a" \
    "${X86_64_DIR}/libBasaltCore.a" \
    -output "${OUTPUT_DIR}/libBasaltCore.a"

# basalt-cli
echo "  basalt-cli..."
lipo -create \
    "${ARM64_DIR}/basalt-cli" \
    "${X86_64_DIR}/basalt-cli" \
    -output "${OUTPUT_DIR}/basalt-cli"

# Basalt
echo "  Basalt..."
lipo -create \
    "${ARM64_DIR}/Basalt" \
    "${X86_64_DIR}/Basalt" \
    -output "${OUTPUT_DIR}/Basalt"

# ============================================================
# Step 4: Create app bundle
# ============================================================
echo ""
echo "=== Creating App Bundle ==="
echo ""

APP_BUNDLE="${OUTPUT_DIR}/Basalt.app"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${OUTPUT_DIR}/Basalt" "${APP_BUNDLE}/Contents/MacOS/Basalt"
cp "${SYMLINK}/Basalt/Info.plist" "${APP_BUNDLE}/Contents/Info.plist"
echo -n "APPLBSLT" > "${APP_BUNDLE}/Contents/PkgInfo"

# Copy icon if available
if [ -f "${SYMLINK}/Resources/Icons/Basalt.icns" ]; then
    cp "${SYMLINK}/Resources/Icons/Basalt.icns" "${APP_BUNDLE}/Contents/Resources/"
fi

# Copy Credits (shown in About window — required by TrueCrypt License III.1.c)
cp "${SYMLINK}/Basalt/Credits.rtf" "${APP_BUNDLE}/Contents/Resources/"

# ============================================================
# Step 5: Ad-hoc code sign
# ============================================================
echo ""
echo "=== Code Signing ==="
echo ""

codesign --force --deep --sign - "${APP_BUNDLE}"
codesign --force --sign - "${OUTPUT_DIR}/basalt-cli"
echo "  Signed Basalt.app and basalt-cli"

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================"
echo "  Universal Build Complete"
echo "============================================"
echo ""

echo "libBasaltCore.a:"
lipo -info "${OUTPUT_DIR}/libBasaltCore.a"
ls -lh "${OUTPUT_DIR}/libBasaltCore.a"
echo ""

echo "basalt-cli:"
lipo -info "${OUTPUT_DIR}/basalt-cli"
ls -lh "${OUTPUT_DIR}/basalt-cli"
echo ""

echo "Basalt.app:"
lipo -info "${APP_BUNDLE}/Contents/MacOS/Basalt"
ls -lh "${APP_BUNDLE}/Contents/MacOS/Basalt"
echo ""

echo "Output directory: ${OUTPUT_DIR}"
