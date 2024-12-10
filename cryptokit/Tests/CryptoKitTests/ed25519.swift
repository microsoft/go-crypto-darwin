// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import XCTest

@testable import CryptoKitSrc

final class Ed25519Tests: XCTestCase {
    func testGenerateKeyEd25519() {
        // Generate a private key
        let privateKeyPointer = generateKeyEd25519()
        XCTAssertNotNil(privateKeyPointer, "Private key generation failed")

        // Validate the private key's length
        let privateKeyData = Data(bytes: privateKeyPointer!, count: 32)
        XCTAssertEqual(privateKeyData.count, 32, "Private key length should be 32 bytes")

        // Free the key
        freeKeyEd25519(privateKeyPointer)
    }

    func testNewPrivateKeyEd25519FromSeed() {
        // Create a seed
        let seed = Data(repeating: 1, count: 32)
        let privateKeyPointer = newPrivateKeyEd25519FromSeed(
            seedPointer: seed.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) },
            seedLength: 32
        )
        XCTAssertNotNil(privateKeyPointer, "Private key generation from seed failed")

        // Validate the private key's length
        let privateKeyData = Data(bytes: privateKeyPointer!, count: 32)
        XCTAssertEqual(privateKeyData.count, 32, "Private key length should be 32 bytes")

        // Free the key
        freeKeyEd25519(privateKeyPointer)
    }

    func testNewPublicKeyEd25519() {
        // Generate a private key
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        // Create a public key from the raw data
        let publicKeyPointer = newPublicKeyEd25519(
            pubPointer: publicKeyData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) },
            pubLength: 32
        )
        XCTAssertNotNil(publicKeyPointer, "Public key generation from raw data failed")

        // Validate the public key's length
        let publicKeyExtracted = Data(bytes: publicKeyPointer!, count: 32)
        XCTAssertEqual(publicKeyExtracted, publicKeyData, "Public key data mismatch")

        // Free the key
        freeKeyEd25519(publicKeyPointer)
    }

    func testSignEd25519() {
        // Generate a private key
        let privateKey = Curve25519.Signing.PrivateKey()
        let privateKeyPointer = UnsafeMutableRawPointer.allocate(
            byteCount: privateKey.rawRepresentation.count,
            alignment: 1
        )
        privateKey.rawRepresentation.copyBytes(to: privateKeyPointer.assumingMemoryBound(to: UInt8.self), count: 32)

        // Sign a message
        let message = "Hello, world!".data(using: .utf8)!
        var signature = Data(repeating: 0, count: 64)
        let result = signature.withUnsafeMutableBytes {
            signEd25519(
                privateKeyPointer: privateKeyPointer,
                messagePointer: message.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) },
                messageLength: message.count,
                sigBuffer: $0.baseAddress!.assumingMemoryBound(to: UInt8.self),
                sigBufferLength: 64
            )
        }

        XCTAssertEqual(result, 64, "Signature generation failed or incorrect length")

        // Free the key
        freeKeyEd25519(privateKeyPointer)
    }

    func testVerifyEd25519() {
        // Generate a key pair
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        // Sign a message
        let originalMessage = "Test message".data(using: .utf8)!
        let signature = try! privateKey.signature(for: originalMessage)

        // Verify the signature
        let publicKeyPointer = UnsafeMutableRawPointer.allocate(
            byteCount: publicKey.rawRepresentation.count,
            alignment: 1
        )
        publicKey.rawRepresentation.copyBytes(to: publicKeyPointer.assumingMemoryBound(to: UInt8.self), count: 32)

        let isValid = originalMessage.withUnsafeBytes { messagePointer in
            signature.withUnsafeBytes { signaturePointer in
                verifyEd25519(
                    publicKeyPointer: publicKeyPointer,
                    messagePointer: messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    messageLength: originalMessage.count,
                    sigPointer: signaturePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    sigLength: signature.count
                )
            }
        }

        XCTAssertEqual(isValid, 1, "Signature verification failed")

        // Free the key
        freeKeyEd25519(publicKeyPointer)
    }
}
