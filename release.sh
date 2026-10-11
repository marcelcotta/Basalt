#!/bin/bash
#
# Build, sign, notarize and package Basalt for distribution.
#
# Produces in build-universal/release/:
#   Basalt.dmg      disk image with Basalt.app (signed, notarized, stapled)
#   basalt-cli.zip  command-line tool (signed, notarized; a bare executable
#                   cannot be stapled, Gatekeeper checks the ticket online)
#
# Prerequisites:
#   - a "Developer ID Application" certificate in the login keychain
#   - notarytool credentials stored once in the keychain:
#       xcrun notarytool store-credentials basalt-notary --key <AuthKey.p8> \
#           --key-id <key id> --issuer <issuer id>
#
# Usage: ./release.sh
#
# Environment:
#   SIGN_IDENTITY   certificate name (default: the Developer ID Application
#                   identity in the keychain, if there is exactly one)
#   NOTARY_PROFILE  notarytool keychain profile (default: basalt-notary)
#   ALLOW_DIRTY=1   release from a working tree with uncommitted changes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
NOTARY_PROFILE="${NOTARY_PROFILE:-basalt-notary}"

die() { echo "error: $*" >&2; exit 1; }

# ============================================================
# Preconditions
# ============================================================
if [ -z "${SIGN_IDENTITY:-}" ]; then
    IDENTITIES="$(security find-identity -v -p codesigning \
        | sed -nE 's/^[^"]*"(Developer ID Application:[^"]*)".*$/\1/p')"
    COUNT="$(printf '%s\n' "${IDENTITIES}" | grep -c . || true)"
    case "${COUNT}" in
        1) SIGN_IDENTITY="${IDENTITIES}" ;;
        0) die "no 'Developer ID Application' certificate in the keychain" ;;
        *) die "several Developer ID Application certificates found; set SIGN_IDENTITY" ;;
    esac
fi
export SIGN_IDENTITY

xcrun notarytool history --keychain-profile "${NOTARY_PROFILE}" >/dev/null 2>&1 \
    || die "notarytool profile '${NOTARY_PROFILE}' is missing or rejected (xcrun notarytool store-credentials)"

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${SCRIPT_DIR}/Basalt/Info.plist")"
HEADER_VERSION="$(sed -nE 's/^#define VERSION_STRING[[:space:]]+"([^"]+)".*/\1/p' "${SCRIPT_DIR}/src/Common/Tcdefs.h")"
[ "${VERSION}" = "${HEADER_VERSION}" ] \
    || die "version mismatch: Info.plist ${VERSION}, Tcdefs.h ${HEADER_VERSION}"

if [ "${ALLOW_DIRTY:-0}" != "1" ] && [ -n "$(git -C "${SCRIPT_DIR}" status --porcelain)" ]; then
    die "uncommitted changes in the working tree (ALLOW_DIRTY=1 to override)"
fi

echo "============================================"
echo "  Basalt ${VERSION} release"
echo "  Identity: ${SIGN_IDENTITY}"
echo "  Notary profile: ${NOTARY_PROFILE}"
echo "============================================"

# Submit a file to the notary service and wait for the verdict.
notarize() {
    local file="$1" out status id
    echo "  Notarizing $(basename "${file}") (this can take a few minutes)..."
    out="$(xcrun notarytool submit "${file}" --keychain-profile "${NOTARY_PROFILE}" \
        --wait --output-format json)" || true
    status="$(printf '%s' "${out}" | plutil -extract status raw -o - - 2>/dev/null || true)"
    id="$(printf '%s' "${out}" | plutil -extract id raw -o - - 2>/dev/null || true)"
    if [ "${status}" != "Accepted" ]; then
        echo "error: notarization of $(basename "${file}") ended with status '${status:-unknown}'" >&2
        if [ -n "${id}" ]; then
            xcrun notarytool log "${id}" --keychain-profile "${NOTARY_PROFILE}" >&2 || true
        fi
        exit 1
    fi
    echo "  Accepted (${id})"
}

# Staple the notarization ticket. Right after acceptance the ticket can be
# unavailable for a moment, so retry.
staple() {
    local file="$1" attempt
    for attempt in 1 2 3 4 5 6; do
        if xcrun stapler staple "${file}" >/dev/null 2>&1; then
            xcrun stapler validate "${file}"
            return 0
        fi
        echo "  Ticket for $(basename "${file}") not available yet (attempt ${attempt}/6)..."
        sleep 20
    done
    die "could not staple $(basename "${file}")"
}

# ============================================================
# Step 1: Build and sign (hardened runtime, secure timestamp)
# ============================================================
bash "${SCRIPT_DIR}/build-universal.sh" release

UNIVERSAL="${SCRIPT_DIR}/build-universal/universal"
APP="${UNIVERSAL}/Basalt.app"
CLI="${UNIVERSAL}/basalt-cli"
[ -d "${APP}" ] && [ -f "${CLI}" ] || die "build output not found in ${UNIVERSAL}"

OUT="${SCRIPT_DIR}/build-universal/release"
rm -rf "${OUT}"
mkdir -p "${OUT}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/basalt-release.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# ============================================================
# Step 2: Notarize and staple the app
# ============================================================
echo ""
echo "=== Basalt.app ==="
ditto -c -k --keepParent "${APP}" "${WORK}/Basalt-app.zip"
notarize "${WORK}/Basalt-app.zip"
staple "${APP}"

# ============================================================
# Step 3: Disk image
# ============================================================
echo ""
echo "=== Basalt.dmg ==="
STAGE="${WORK}/dmg"
mkdir -p "${STAGE}"
ditto "${APP}" "${STAGE}/Basalt.app"
ln -s /Applications "${STAGE}/Applications"
hdiutil create -volname "Basalt" -srcfolder "${STAGE}" -fs HFS+ -format UDZO -ov \
    "${OUT}/Basalt.dmg" >/dev/null
codesign --force --timestamp --sign "${SIGN_IDENTITY}" "${OUT}/Basalt.dmg"
notarize "${OUT}/Basalt.dmg"
staple "${OUT}/Basalt.dmg"

# ============================================================
# Step 4: Command-line tool
# ============================================================
echo ""
echo "=== basalt-cli.zip ==="
ditto -c -k "${CLI}" "${OUT}/basalt-cli.zip"
notarize "${OUT}/basalt-cli.zip"

# ============================================================
# Step 5: Final checks
# ============================================================
echo ""
echo "=== Verification ==="
codesign -dvv "${APP}" 2>&1 | grep -E "^(Authority|TeamIdentifier|Timestamp|CodeDirectory)" || true
spctl --assess --type execute --verbose=2 "${APP}"
spctl --assess --type open --context context:primary-signature --verbose=2 "${OUT}/Basalt.dmg"

echo ""
echo "============================================"
echo "  Release ${VERSION} ready: ${OUT}"
echo "============================================"
( cd "${OUT}" && shasum -a 256 Basalt.dmg basalt-cli.zip )
