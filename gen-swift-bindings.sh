#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# remove any existing per-arch syso files
rm -f internal/cryptokit/Cryptokit_*.syso

cd cryptokit

rm -rf .build

echo "Building Swift bindings..."

for arch in arm64 x86_64; do
    echo "Building for ${arch}..."

    # build only for the requested architecture
    xcrun swift build -c release --arch ${arch}

    # prefer a static archive if present (libCryptoKitSrc.a), else try to find module/object files
    if [ -f .build/*-apple-macosx/release/libCryptoKitSrc.a ]; then
        # copy the static archive as the .syso
        objfile=$(ls .build/*-apple-macosx/release/libCryptoKitSrc.a | head -n1)
    elif [ -f .build/apple/Products/Release/CryptoKitSrc_Module.o ]; then
        objfile=.build/apple/Products/Release/CryptoKitSrc_Module.o
    elif [ -f .build/apple/Products/Release/CryptoKitSrc.o ]; then
        objfile=.build/apple/Products/Release/CryptoKitSrc.o
    else
        # try to find any CryptoKitSrc object under .build
        found=$(find .build -name "CryptoKitSrc*.o" | head -n1 || true)
        if [ -n "${found}" ]; then
            objfile=${found}
        else
            echo "error: could not find built object or archive for ${arch}"
            exit 1
        fi
    fi

    # copy to per-arch syso
    if [ "${arch}" = "arm64" ]; then
        dest="../internal/cryptokit/CryptoKit_arm64.syso"
    else
        # map x86_64 to amd64 naming used by Go
        dest="../internal/cryptokit/CryptoKit_amd64.syso"
    fi
    cp "${objfile}" "${dest}"

    # clean build artifacts between architectures to avoid mixing
    rm -rf .build
done

echo "Build complete."
