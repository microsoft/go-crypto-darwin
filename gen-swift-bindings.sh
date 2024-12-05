#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

cd cryptokit

rm -rf ./*.o .build

echo "Building Swift bindings..."
xcrun swift build -c release --arch arm64 --arch x86_64

cp .build/apple/Products/Release/CryptoKitSrc.o CryptoKit.o

echo "Build complete."
