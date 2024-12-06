#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

rm -f internal/cryptokit/CryptoKit.o

cd cryptokit

rm -rf .build

echo "Building Swift bindings..."
xcrun swift build -c release --arch arm64 --arch x86_64

cp .build/apple/Products/Release/CryptoKitSrc.o ../internal/cryptokit/CryptoKit.o

echo "Build complete."
