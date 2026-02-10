#!/bin/bash
#
# Build universal (arm64 + x86_64) binaries for TrueCrypt macOS
# Produces: libTrueCryptCore.a, truecrypt-cli, TrueCryptMac.app
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
echo "  TrueCrypt Universal Binary Build"
echo "  Config: ${BUILD_CONFIG}"
echo "============================================"
echo ""

# Clean previous universal build
rm -rf "${BUILD_ROOT}"
mkdir -p "${ARM64_DIR}" "${X86_64_DIR}" "${OUTPUT_DIR}"

# ============================================================
# Helper: build libTrueCryptCore.a for a specific architecture
# ============================================================
build_core_lib() {
    local ARCH="$1"
    local OUT_DIR="$2"

    echo ""
    echo "=== Building libTrueCryptCore.a (${ARCH}) ==="
    echo ""

    # Clean object files from previous build
    for DIR in Platform Volume Driver/Fuse Core; do
        PROJ=$(echo "${DIR}" | cut -d/ -f1)
        rm -f "${SYMLINK}/${DIR}/${PROJ}.a"
        find "${SYMLINK}/${DIR}" -name '*.o' -delete 2>/dev/null || true
    done
    # Also clean Crypto and Common .o files (they live outside Volume/)
    find "${SYMLINK}/Crypto" -name '*.o' -delete 2>/dev/null || true
    find "${SYMLINK}/Common" -name '*.o' -delete 2>/dev/null || true
    rm -f "${SYMLINK}/libTrueCryptCore.a"

    # Build with architecture override
    # TARGET_ARCH controls which arch-specific crypto sources are included
    make -C "${SYMLINK}" BASE_DIR="${SYMLINK}" NOASM=1 \
        TARGET_ARCH="${ARCH}" \
        TC_EXTRA_CFLAGS="-arch ${ARCH}" \
        TC_EXTRA_CXXFLAGS="-arch ${ARCH}" \
        TC_EXTRA_LFLAGS="-arch ${ARCH}" \
        libTrueCryptCore

    # Verify architecture
    echo "  Verifying ${ARCH}..."
    lipo -info "${SYMLINK}/libTrueCryptCore.a" 2>/dev/null || true

    # Copy to output
    cp "${SYMLINK}/libTrueCryptCore.a" "${OUT_DIR}/libTrueCryptCore.a"
}

# ============================================================
# Helper: build CLI for a specific architecture
# ============================================================
build_cli() {
    local ARCH="$1"
    local OUT_DIR="$2"

    echo ""
    echo "=== Building truecrypt-cli (${ARCH}) ==="
    echo ""

    # Clean CLI objects
    rm -f "${SYMLINK}/CLI/"*.o "${SYMLINK}/CLI/truecrypt-cli"

    make -C "${SYMLINK}" BASE_DIR="${SYMLINK}" NOASM=1 NOTEST=1 \
        TARGET_ARCH="${ARCH}" \
        TC_EXTRA_CFLAGS="-arch ${ARCH}" \
        TC_EXTRA_CXXFLAGS="-arch ${ARCH}" \
        TC_EXTRA_LFLAGS="-arch ${ARCH}" \
        cli

    cp "${SYMLINK}/CLI/truecrypt-cli" "${OUT_DIR}/truecrypt-cli"
}

# ============================================================
# Helper: build SwiftUI app for a specific architecture
# ============================================================
build_swiftui() {
    local ARCH="$1"
    local OUT_DIR="$2"
    local CORE_LIB="${OUT_DIR}/libTrueCryptCore.a"

    echo ""
    echo "=== Building TrueCryptMac (${ARCH}) ==="
    echo ""

    local SDK_PATH
    SDK_PATH="$(xcrun --show-sdk-path)"
    local MIN_MACOS="12.0"
    local BRIDGE_DIR="${SYMLINK}/TrueCryptMac/Bridge"
    local APP_DIR="${SYMLINK}/TrueCryptMac/App"
    local OBJ_DIR="${OUT_DIR}/obj"
    mkdir -p "${OBJ_DIR}"

    # Compiler flags
    local COMMON_FLAGS="-arch ${ARCH} -mmacosx-version-min=${MIN_MACOS} -isysroot ${SDK_PATH}"
    local CXX_FLAGS="${COMMON_FLAGS} -std=c++14 -stdlib=libc++ -I${SYMLINK} -I${SYMLINK}/Crypto"
    CXX_FLAGS="${CXX_FLAGS} -DTC_UNIX -DTC_BSD -DTC_MACOSX -D__STDC_WANT_LIB_EXT1__=1"
    CXX_FLAGS="${CXX_FLAGS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES"
    local OBJCXX_FLAGS="${CXX_FLAGS} -fobjc-arc"

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
    local BRIDGING_HEADER="${BRIDGE_DIR}/TrueCryptMac-Bridging-Header.h"

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
        -module-name TrueCryptMac \
        -emit-module -emit-module-path "${OBJ_DIR}/TrueCryptMac.swiftmodule" \
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

    local FUSE_LIBS
    FUSE_LIBS="$(pkg-config fuse --libs 2>/dev/null || echo '-losxfuse')"

    local SWIFT_OBJS
    SWIFT_OBJS=$(find "${OBJ_DIR}" -name "*.swift.o" -type f | sort)

    clang++ ${LINK_FLAGS} \
        "${OBJ_DIR}"/TCCoreBridge.o \
        "${OBJ_DIR}"/TCCocoaCallback.o \
        ${SWIFT_OBJS} \
        "${CORE_LIB}" \
        ${FUSE_LIBS} \
        -lc++ \
        -framework AppKit \
        -framework Security \
        -framework SwiftUI \
        -framework Combine \
        -L "${SWIFT_LIB_DIR}" \
        -Wl,-rpath,/usr/lib/swift \
        -o "${OUT_DIR}/TrueCryptMac"
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

# libTrueCryptCore.a
echo "  libTrueCryptCore.a..."
lipo -create \
    "${ARM64_DIR}/libTrueCryptCore.a" \
    "${X86_64_DIR}/libTrueCryptCore.a" \
    -output "${OUTPUT_DIR}/libTrueCryptCore.a"

# truecrypt-cli
echo "  truecrypt-cli..."
lipo -create \
    "${ARM64_DIR}/truecrypt-cli" \
    "${X86_64_DIR}/truecrypt-cli" \
    -output "${OUTPUT_DIR}/truecrypt-cli"

# TrueCryptMac
echo "  TrueCryptMac..."
lipo -create \
    "${ARM64_DIR}/TrueCryptMac" \
    "${X86_64_DIR}/TrueCryptMac" \
    -output "${OUTPUT_DIR}/TrueCryptMac"

# ============================================================
# Step 4: Create app bundle
# ============================================================
echo ""
echo "=== Creating App Bundle ==="
echo ""

APP_BUNDLE="${OUTPUT_DIR}/TrueCryptMac.app"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${OUTPUT_DIR}/TrueCryptMac" "${APP_BUNDLE}/Contents/MacOS/TrueCryptMac"
cp "${SYMLINK}/TrueCryptMac/Info.plist" "${APP_BUNDLE}/Contents/Info.plist"
echo -n "APPLTRUE" > "${APP_BUNDLE}/Contents/PkgInfo"

# Copy icon if available
if [ -f "${SYMLINK}/Resources/Icons/TrueCrypt.icns" ]; then
    cp "${SYMLINK}/Resources/Icons/TrueCrypt.icns" "${APP_BUNDLE}/Contents/Resources/"
fi

# ============================================================
# Step 5: Ad-hoc code sign
# ============================================================
echo ""
echo "=== Code Signing ==="
echo ""

codesign --force --deep --sign - "${APP_BUNDLE}"
codesign --force --sign - "${OUTPUT_DIR}/truecrypt-cli"
echo "  Signed TrueCryptMac.app and truecrypt-cli"

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================"
echo "  Universal Build Complete"
echo "============================================"
echo ""

echo "libTrueCryptCore.a:"
lipo -info "${OUTPUT_DIR}/libTrueCryptCore.a"
ls -lh "${OUTPUT_DIR}/libTrueCryptCore.a"
echo ""

echo "truecrypt-cli:"
lipo -info "${OUTPUT_DIR}/truecrypt-cli"
ls -lh "${OUTPUT_DIR}/truecrypt-cli"
echo ""

echo "TrueCryptMac.app:"
lipo -info "${APP_BUNDLE}/Contents/MacOS/TrueCryptMac"
ls -lh "${APP_BUNDLE}/Contents/MacOS/TrueCryptMac"
echo ""

echo "Output directory: ${OUTPUT_DIR}"
