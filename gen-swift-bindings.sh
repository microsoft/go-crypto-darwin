#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# remove any existing per-arch syso files
rm -f internal/cryptokit/CryptoKit_*.syso

cd cryptokit

rm -rf .build

echo "Building Swift bindings..."

# build once and split the resulting object by architecture using lipo
xcrun swift build -c release --arch arm64 --arch x86_64

# locate the built object (on macOS 15+ it may be CryptoKitSrc_Module.o)
if [ -f .build/apple/Products/Release/CryptoKitSrc_Module.o ]; then
    objfile=.build/apple/Products/Release/CryptoKitSrc_Module.o
elif [ -f .build/apple/Products/Release/CryptoKitSrc.o ]; then
    objfile=.build/apple/Products/Release/CryptoKitSrc.o
else
    found=$(find .build -name "CryptoKitSrc*.o" | head -n1 || true)
    if [ -n "${found}" ]; then
        objfile=${found}
    else
        echo "error: could not find built object file"
        exit 1
    fi
fi

for arch in arm64 x86_64; do
    echo "Processing ${arch}..."

    if [ "${arch}" = "arm64" ]; then
        dest="../internal/cryptokit/CryptoKit_arm64.syso"
    else
        # map x86_64 to amd64 naming used by Go
        dest="../internal/cryptokit/CryptoKit_amd64.syso"
    fi

    # try to extract the requested arch from the (possibly universal) object
    if lipo -thin ${arch} "${objfile}" -output "${dest}"; then
        echo "Created ${dest} via lipo extract"
    else
        # lipo failed (object may not be fat) -- fall back to copying the object directly
        echo "lipo extract failed for ${arch}, copying object as-is to ${dest}"
        cp "${objfile}" "${dest}"
    fi

done

# clean build artifacts
rm -rf .build

echo "Build complete."
