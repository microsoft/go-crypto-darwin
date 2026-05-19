#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

cd cryptokit

# remove any existing per-arch syso files
rm -f ../internal/cryptokit/CryptoKit_*.syso

# Check if the Xcode version matches the one used for the previous build.
version_file="../internal/cryptokit/xcodebuild_version.txt"
if [ -f "${version_file}" ]; then
    current_version="$(xcodebuild -version)"
    previous_version="$(cat "${version_file}")"
    if [ "${current_version}" != "${previous_version}" ]; then
        echo "WARNING: Xcode version has changed since the last build." >&2
        echo "  Previous:" >&2
        printf '%s\n' "${previous_version}" >&2
        echo "  Current:" >&2
        printf '%s\n' "${current_version}" >&2
        echo "  See docs/swift-bindings.md for details on reproducibility." >&2
    fi
fi

# Record the Xcode version used for this build.
xcodebuild -version > "${version_file}"

echo "Building Swift bindings with swiftc..."

for arch in arm64 x86_64; do
    if [ "${arch}" = "arm64" ]; then
        dest="../internal/cryptokit/CryptoKit_arm64.syso"
    else
        # map x86_64 to amd64 naming used by Go
        dest="../internal/cryptokit/CryptoKit_amd64.syso"
    fi

    echo "Compiling for ${arch} → ${dest}"

    xcrun swiftc \
        -emit-object \
        -parse-as-library \
        -whole-module-optimization \
        -target ${arch}-apple-macosx13.0 \
        -import-bridging-header Sources/CryptoKitC/include/cryptokit.h \
        Sources/CryptoKitSrc/cryptokit.swift \
        -o "${dest}"
done

echo "Build complete."
