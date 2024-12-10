// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest

@testable import CryptoKitSrc

final class Ed25519CryptoTests: XCTestCase {

    func testGenerateKeyEd25519() {
        var keyBuffer = [UInt8](repeating: 0, count: publicKeySizeEd25519 + seedSizeEd25519)
        generateKeyEd25519(keyPointer: &keyBuffer)

        // Validate that the key buffer has been filled
        XCTAssertFalse(keyBuffer.allSatisfy({ $0 == 0 }), "Key buffer should not be empty.")
    }

    func testNewPrivateKeyEd25519FromSeed() {
        var keyBuffer = [UInt8](repeating: 0, count: publicKeySizeEd25519 + seedSizeEd25519)
        let seed = Data((0..<seedSizeEd25519).map { _ in UInt8.random(in: 0...255) })
        let seedBuffer = seed.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }

        let result = newPrivateKeyEd25519FromSeed(keyPointer: &keyBuffer, seedPointer: seedBuffer)

        // Validate the private key creation result
        XCTAssertEqual(result, 0, "Expected private key creation to succeed.")
    }

    func testNewPublicKeyEd25519() {
        var keyBuffer = [UInt8](repeating: 0, count: publicKeySizeEd25519)
        let publicKeyData = Data((0..<publicKeySizeEd25519).map { _ in UInt8.random(in: 0...255) })
        let pubPointer = publicKeyData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }

        let result = newPublicKeyEd25519(keyPointer: &keyBuffer, pubPointer: pubPointer)

        // Validate the public key creation result
        XCTAssertEqual(result, 0, "Expected public key creation to succeed.")
    }

    func testSignEd25519() {
        var keyBuffer = [UInt8](repeating: 0, count: publicKeySizeEd25519 + seedSizeEd25519)
        generateKeyEd25519(keyPointer: &keyBuffer)

        let message = "Test message".data(using: .utf8)!
        var sigBuffer = [UInt8](repeating: 0, count: signatureSizeEd25519)

        keyBuffer.withUnsafeBytes { keyPointer in
            message.withUnsafeBytes { messagePointer in
                sigBuffer.withUnsafeMutableBufferPointer { sigPointer in
                    let result = signEd25519(
                        privateKeyPointer: keyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        messagePointer: messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        messageLength: message.count,
                        sigBuffer: sigPointer.baseAddress!
                    )
                    XCTAssertGreaterThan(result, 0, "Expected signature to be generated successfully.")
                }
            }
        }
    }

    func testVerifyEd25519() {
        var keyBuffer = [UInt8](repeating: 0, count: publicKeySizeEd25519 + seedSizeEd25519)
        generateKeyEd25519(keyPointer: &keyBuffer)

        let message = "Test message".data(using: .utf8)!
        var sigBuffer = [UInt8](repeating: 0, count: signatureSizeEd25519)

        keyBuffer.withUnsafeBytes { keyPointer in
            let privateKeyPointer = keyPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            let publicKeyPointer = privateKeyPointer + seedSizeEd25519

            message.withUnsafeBytes { messagePointer in
                sigBuffer.withUnsafeMutableBufferPointer { sigPointer in
                    let signResult = signEd25519(
                        privateKeyPointer: privateKeyPointer,
                        messagePointer: messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        messageLength: message.count,
                        sigBuffer: sigPointer.baseAddress!
                    )
                    XCTAssertGreaterThan(signResult, 0, "Expected signature to be generated successfully.")

                    let verifyResult = verifyEd25519(
                        publicKeyPointer: publicKeyPointer,
                        messagePointer: messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        messageLength: message.count,
                        sigPointer: sigPointer.baseAddress!
                    )
                    XCTAssertEqual(verifyResult, 1, "Expected the signature to be valid.")
                }
            }
        }
    }
}
