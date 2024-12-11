#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

rm -f internal/cryptokit/CryptoKit.o
rm -f internal/cryptokit/CryptoKit.h

cd cryptokit

rm -rf .build

echo "Building Swift bindings..."
xcrun swift build -c release --arch arm64 --arch x86_64

cp .build/apple/Products/Release/CryptoKitSrc.o ../internal/cryptokit/CryptoKit.o
cp .build/apple/Intermediates.noindex/GeneratedModuleMaps/macosx/CryptoKitSrc-Swift.h ../internal/cryptokit/CryptoKit.h

echo "Build complete."
