#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

cd cryptokit

# remove any existing per-arch syso files
rm -f ../internal/cryptokit/CryptoKit_*.syso

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
        Sources/CryptoKitSrc/cryptokit.swift \
        -o "${dest}"
done

echo "Build complete."
