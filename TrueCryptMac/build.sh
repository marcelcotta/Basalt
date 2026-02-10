#!/bin/bash
#
# Build script for TrueCryptMac — SwiftUI + ObjC++ Bridge + libTrueCryptCore
# Usage: ./build.sh [release|debug]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${SCRIPT_DIR}/build"
BUILD_CONFIG="${1:-debug}"

# Use symlink to handle spaces in path
SYMLINK="/tmp/truecrypt-build"
ln -sfn "${ROOT_DIR}" "${SYMLINK}"

# Paths (all via symlink — no spaces)
SRC_ROOT="${SYMLINK}"
BRIDGE_DIR="${SYMLINK}/TrueCryptMac/Bridge"
APP_DIR="${SYMLINK}/TrueCryptMac/App"
CORE_LIB="${SYMLINK}/libTrueCryptCore.a"
APP_BUNDLE="${BUILD_DIR}/TrueCryptMac.app"

# SDK & arch
SDK_PATH="$(xcrun --show-sdk-path)"
ARCH="$(uname -m)"
MIN_MACOS="12.0"

echo "=== TrueCryptMac Build ==="
echo "Config:    ${BUILD_CONFIG}"
echo "Arch:      ${ARCH}"
echo "SDK:       ${SDK_PATH}"
echo "Core lib:  ${CORE_LIB}"
echo ""

# Step 0: Ensure libTrueCryptCore.a exists
if [ ! -f "${CORE_LIB}" ]; then
    echo "Building libTrueCryptCore.a first..."
    make -C "${SYMLINK}" BASE_DIR="${SYMLINK}" NOASM=1 libTrueCryptCore
fi

if [ ! -f "${CORE_LIB}" ]; then
    echo "Error: libTrueCryptCore.a not found"
    echo "Build it first: make BASE_DIR=/tmp/truecrypt-build NOASM=1 libTrueCryptCore"
    exit 1
fi

# Build dir (use symlink path too)
BUILD_OBJ="${SYMLINK}/TrueCryptMac/build/obj"
mkdir -p "${BUILD_OBJ}"

# Compiler flags (no spaces in paths now)
COMMON_FLAGS="-arch ${ARCH} -mmacosx-version-min=${MIN_MACOS} -isysroot ${SDK_PATH}"
CXX_FLAGS="${COMMON_FLAGS} -std=c++14 -stdlib=libc++ -I${SRC_ROOT} -I${SRC_ROOT}/Crypto"
CXX_FLAGS="${CXX_FLAGS} -DTC_UNIX -DTC_BSD -DTC_MACOSX -D__STDC_WANT_LIB_EXT1__=1"
CXX_FLAGS="${CXX_FLAGS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES"
OBJCXX_FLAGS="${CXX_FLAGS} -fobjc-arc"

if [ "${BUILD_CONFIG}" = "release" ]; then
    OBJCXX_FLAGS="${OBJCXX_FLAGS} -O2"
    SWIFT_FLAGS="-O"
else
    OBJCXX_FLAGS="${OBJCXX_FLAGS} -DDEBUG -g"
    SWIFT_FLAGS="-Onone -g"
fi

FUSE_LIBS="$(pkg-config fuse --libs 2>/dev/null || echo '-losxfuse')"

# Step 1: Compile ObjC++ Bridge files
echo "Compiling Bridge..."
for src in "${BRIDGE_DIR}"/*.mm; do
    base="$(basename "${src}" .mm)"
    obj="${BUILD_OBJ}/${base}.o"
    echo "  ${base}.mm"
    clang++ ${OBJCXX_FLAGS} -c "${src}" -o "${obj}"
done

# Step 2: Compile Swift files
echo "Compiling Swift..."
SWIFT_SOURCES=$(find "${APP_DIR}" -name "*.swift" -type f | sort)
BRIDGING_HEADER="${BRIDGE_DIR}/TrueCryptMac-Bridging-Header.h"

# Generate output-file-map for swiftc (maps each .swift → .o in build dir)
OUTPUT_FILE_MAP="${BUILD_OBJ}/output-file-map.json"
echo "{" > "${OUTPUT_FILE_MAP}"
FIRST=1
for src in ${SWIFT_SOURCES}; do
    base="$(basename "${src}" .swift)"
    obj="${BUILD_OBJ}/${base}.swift.o"
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
    -emit-module -emit-module-path "${BUILD_OBJ}/TrueCryptMac.swiftmodule" \
    -emit-object \
    -parse-as-library \
    -output-file-map "${OUTPUT_FILE_MAP}" \
    ${SWIFT_SOURCES}

# Step 3: Link everything
echo "Linking TrueCryptMac..."
LINK_FLAGS="-arch ${ARCH} -mmacosx-version-min=${MIN_MACOS} -isysroot ${SDK_PATH}"
LINK_FLAGS="${LINK_FLAGS} -stdlib=libc++ -Wl,-dead_strip"

# Find Swift library path
SWIFT_LIB_DIR="$(dirname "$(xcrun --find swiftc)")/../lib/swift/macosx"

SWIFT_OBJS=$(find "${BUILD_OBJ}" -name "*.swift.o" -type f | sort)

clang++ ${LINK_FLAGS} \
    "${BUILD_OBJ}"/TCCoreBridge.o \
    "${BUILD_OBJ}"/TCCocoaCallback.o \
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
    -o "${BUILD_OBJ}/../TrueCryptMac"

# Step 4: Create app bundle
echo "Creating app bundle..."
mkdir -p "${BUILD_DIR}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${BUILD_OBJ}/../TrueCryptMac" "${APP_BUNDLE}/Contents/MacOS/TrueCryptMac"
cp "${SYMLINK}/TrueCryptMac/Info.plist" "${APP_BUNDLE}/Contents/Info.plist"

echo -n "APPLTRUE" > "${APP_BUNDLE}/Contents/PkgInfo"

# Copy icon if available
if [ -f "${SYMLINK}/Resources/Icons/TrueCrypt.icns" ]; then
    cp "${SYMLINK}/Resources/Icons/TrueCrypt.icns" "${APP_BUNDLE}/Contents/Resources/"
fi

# Step 5: Ad-hoc code sign
echo "Code signing..."
codesign --force --deep --sign - "${APP_BUNDLE}"

echo ""
echo "=== Build complete ==="
echo "App bundle: ${APP_BUNDLE}"
echo ""
file "${APP_BUNDLE}/Contents/MacOS/TrueCryptMac"
codesign -dvv "${APP_BUNDLE}" 2>&1 | head -5
ls -lh "${APP_BUNDLE}/Contents/MacOS/TrueCryptMac"
