#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

rm -f internal/cryptokit/CryptoKit.o

cd cryptokit

rm -rf .build

echo "Building Swift bindings..."
xcrun swift build -c release --arch arm64 --arch x86_64

# on macOS 15+ it generates a CryptoKitSrc_Module.o
if [ -f .build/apple/Products/Release/CryptoKitSrc_Module.o ]; then
    cp .build/apple/Products/Release/CryptoKitSrc_Module.o ../internal/cryptokit/CryptoKit.o
else [ -f .build/apple/Products/Release/CryptoKitSrc.o ];
    cp .build/apple/Products/Release/CryptoKitSrc.o ../internal/cryptokit/CryptoKit.o
fi

echo "Build complete."
