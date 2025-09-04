#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# remove any existing per-arch syso files
rm -f internal/cryptokit/CryptoKit_*.syso

cd cryptokit

rm -rf .build

echo "Building Swift bindings..."

for arch in arm64 x86_64; do
    echo "Building for ${arch}..."

    xcrun swift build -c release --arch ${arch}

    if [ "${arch}" = "arm64" ]; then
        dest="../internal/cryptokit/CryptoKit_arm64.syso"
    else
        # map x86_64 to amd64 naming used by Go
        dest="../internal/cryptokit/CryptoKit_amd64.syso"
    fi
    ld -r -arch ${arch} -o "${dest}" ".build/${arch}-apple-macosx/release/libCryptoKitSrc.a"

    # clean build artifacts between architectures to avoid mixing
    rm -rf .build
done

echo "Build complete."
