// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import CryptoKitC
import Foundation
import XCTest

@testable import CryptoKitSrc

final class MLDSATests: XCTestCase {

    // MARK: - ML-DSA Support Detection Tests

    #if compiler(>=6.2)
    @available(macOS 26.0, *)
    func testMLDSASupportDetection() {
        let isSupported = go_supportsMLDSA()
        XCTAssertEqual(isSupported, 1, "ML-DSA should be supported on macOS 26.0+")
    }
    #endif

    // MARK: - ML-DSA-65 Tests

    #if compiler(>=6.2)
    @available(macOS 26.0, *)
    func testMLDSA65KeyGeneration() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let result = go_generateKeyMLDSA65(&seed, 32)

        XCTAssertEqual(result, 0, "Key generation should succeed")

        let allZeros = [UInt8](repeating: 0, count: 32)
        XCTAssertNotEqual(seed, allZeros, "Generated seed should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLDSA65DerivePublicKey() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA65(&seed, 32)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        var publicKey = [UInt8](repeating: 0, count: 1952)
        let deriveResult = go_derivePublicKeyMLDSA65(
            seed,
            32,
            &publicKey,
            1952
        )

        XCTAssertEqual(deriveResult, 0, "Public key derivation should succeed")

        let allZeros = [UInt8](repeating: 0, count: 1952)
        XCTAssertNotEqual(publicKey, allZeros, "Derived public key should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLDSA65SignVerify() throws {
        // Generate key
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA65(&seed, 32)
        XCTAssertEqual(genResult, 0)

        // Derive public key
        var publicKey = [UInt8](repeating: 0, count: 1952)
        let deriveResult = go_derivePublicKeyMLDSA65(seed, 32, &publicKey, 1952)
        XCTAssertEqual(deriveResult, 0)

        // Sign
        let message: [UInt8] = Array("test message".utf8)
        var signature = [UInt8](repeating: 0, count: 3309)
        var signatureLen: Int = 3309
        let emptyContext: [UInt8] = []
        let signResult = go_signMLDSA65(
            seed,
            32,
            message,
            message.count,
            emptyContext,
            0,
            &signature,
            &signatureLen
        )
        XCTAssertEqual(signResult, 0, "Signing should succeed")
        XCTAssertGreaterThan(signatureLen, 0, "Signature length should be non-zero")

        // Verify
        let verifyResult = go_verifyMLDSA65(
            publicKey,
            1952,
            message,
            message.count,
            emptyContext,
            0,
            signature,
            signatureLen
        )
        XCTAssertEqual(verifyResult, 0, "Verification should succeed")

        // Verify with wrong message should fail
        var wrongMessage = message
        wrongMessage[0] ^= 0x80
        let badVerifyResult = go_verifyMLDSA65(
            publicKey,
            1952,
            wrongMessage,
            wrongMessage.count,
            emptyContext,
            0,
            signature,
            signatureLen
        )
        XCTAssertNotEqual(badVerifyResult, 0, "Verification with wrong message should fail")
    }

    @available(macOS 26.0, *)
    func testMLDSA65SignVerifyWithContext() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA65(&seed, 32)
        XCTAssertEqual(genResult, 0)

        var publicKey = [UInt8](repeating: 0, count: 1952)
        let deriveResult = go_derivePublicKeyMLDSA65(seed, 32, &publicKey, 1952)
        XCTAssertEqual(deriveResult, 0)

        let message: [UInt8] = Array("test message".utf8)
        let context: [UInt8] = Array("my context".utf8)

        // Sign with context
        var signature = [UInt8](repeating: 0, count: 3309)
        var signatureLen: Int = 3309
        let signResult = go_signMLDSA65(
            seed,
            32,
            message,
            message.count,
            context,
            context.count,
            &signature,
            &signatureLen
        )
        XCTAssertEqual(signResult, 0, "Signing with context should succeed")

        // Verify with correct context
        let verifyResult = go_verifyMLDSA65(
            publicKey,
            1952,
            message,
            message.count,
            context,
            context.count,
            signature,
            signatureLen
        )
        XCTAssertEqual(verifyResult, 0, "Verification with correct context should succeed")

        // Verify with wrong context should fail
        let wrongContext: [UInt8] = Array("wrong context".utf8)
        let badVerifyResult = go_verifyMLDSA65(
            publicKey,
            1952,
            message,
            message.count,
            wrongContext,
            wrongContext.count,
            signature,
            signatureLen
        )
        XCTAssertNotEqual(badVerifyResult, 0, "Verification with wrong context should fail")

        // Verify with no context should fail
        let emptyContext: [UInt8] = []
        let noCtxResult = go_verifyMLDSA65(
            publicKey,
            1952,
            message,
            message.count,
            emptyContext,
            0,
            signature,
            signatureLen
        )
        XCTAssertNotEqual(noCtxResult, 0, "Verification without context should fail for context-signed message")
    }

    @available(macOS 26.0, *)
    func testMLDSA65ValidatePublicKey() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA65(&seed, 32)
        XCTAssertEqual(genResult, 0)

        var publicKey = [UInt8](repeating: 0, count: 1952)
        let deriveResult = go_derivePublicKeyMLDSA65(seed, 32, &publicKey, 1952)
        XCTAssertEqual(deriveResult, 0)

        // Valid public key should pass
        let validResult = go_validatePublicKeyMLDSA65(publicKey, 1952)
        XCTAssertEqual(validResult, 0, "Valid public key should pass validation")
    }

    @available(macOS 26.0, *)
    func testMLDSA65DeterministicPublicKey() throws {
        // Same seed should produce the same public key
        let seed = [UInt8](repeating: 42, count: 32)

        var publicKey1 = [UInt8](repeating: 0, count: 1952)
        let result1 = go_derivePublicKeyMLDSA65(seed, 32, &publicKey1, 1952)
        XCTAssertEqual(result1, 0)

        var publicKey2 = [UInt8](repeating: 0, count: 1952)
        let result2 = go_derivePublicKeyMLDSA65(seed, 32, &publicKey2, 1952)
        XCTAssertEqual(result2, 0)

        XCTAssertEqual(publicKey1, publicKey2, "Same seed should produce same public key")
    }

    @available(macOS 26.0, *)
    func testMLDSA65UniqueKeys() throws {
        var seed1 = [UInt8](repeating: 0, count: 32)
        let gen1 = go_generateKeyMLDSA65(&seed1, 32)
        XCTAssertEqual(gen1, 0)

        var seed2 = [UInt8](repeating: 0, count: 32)
        let gen2 = go_generateKeyMLDSA65(&seed2, 32)
        XCTAssertEqual(gen2, 0)

        XCTAssertNotEqual(seed1, seed2, "Two generated seeds should differ")

        var pub1 = [UInt8](repeating: 0, count: 1952)
        let d1 = go_derivePublicKeyMLDSA65(seed1, 32, &pub1, 1952)
        XCTAssertEqual(d1, 0)

        var pub2 = [UInt8](repeating: 0, count: 1952)
        let d2 = go_derivePublicKeyMLDSA65(seed2, 32, &pub2, 1952)
        XCTAssertEqual(d2, 0)

        XCTAssertNotEqual(pub1, pub2, "Two generated public keys should differ")
    }

    // MARK: - ML-DSA-87 Tests

    @available(macOS 26.0, *)
    func testMLDSA87KeyGeneration() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let result = go_generateKeyMLDSA87(&seed, 32)

        XCTAssertEqual(result, 0, "Key generation should succeed")

        let allZeros = [UInt8](repeating: 0, count: 32)
        XCTAssertNotEqual(seed, allZeros, "Generated seed should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLDSA87DerivePublicKey() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA87(&seed, 32)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        var publicKey = [UInt8](repeating: 0, count: 2592)
        let deriveResult = go_derivePublicKeyMLDSA87(
            seed,
            32,
            &publicKey,
            2592
        )

        XCTAssertEqual(deriveResult, 0, "Public key derivation should succeed")

        let allZeros = [UInt8](repeating: 0, count: 2592)
        XCTAssertNotEqual(publicKey, allZeros, "Derived public key should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLDSA87SignVerify() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA87(&seed, 32)
        XCTAssertEqual(genResult, 0)

        var publicKey = [UInt8](repeating: 0, count: 2592)
        let deriveResult = go_derivePublicKeyMLDSA87(seed, 32, &publicKey, 2592)
        XCTAssertEqual(deriveResult, 0)

        // Sign
        let message: [UInt8] = Array("test message".utf8)
        var signature = [UInt8](repeating: 0, count: 4627)
        var signatureLen: Int = 4627
        let emptyContext: [UInt8] = []
        let signResult = go_signMLDSA87(
            seed,
            32,
            message,
            message.count,
            emptyContext,
            0,
            &signature,
            &signatureLen
        )
        XCTAssertEqual(signResult, 0, "Signing should succeed")
        XCTAssertGreaterThan(signatureLen, 0, "Signature length should be non-zero")

        // Verify
        let verifyResult = go_verifyMLDSA87(
            publicKey,
            2592,
            message,
            message.count,
            emptyContext,
            0,
            signature,
            signatureLen
        )
        XCTAssertEqual(verifyResult, 0, "Verification should succeed")

        // Verify with wrong message should fail
        var wrongMessage = message
        wrongMessage[0] ^= 0x80
        let badVerifyResult = go_verifyMLDSA87(
            publicKey,
            2592,
            wrongMessage,
            wrongMessage.count,
            emptyContext,
            0,
            signature,
            signatureLen
        )
        XCTAssertNotEqual(badVerifyResult, 0, "Verification with wrong message should fail")
    }

    @available(macOS 26.0, *)
    func testMLDSA87SignVerifyWithContext() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA87(&seed, 32)
        XCTAssertEqual(genResult, 0)

        var publicKey = [UInt8](repeating: 0, count: 2592)
        let deriveResult = go_derivePublicKeyMLDSA87(seed, 32, &publicKey, 2592)
        XCTAssertEqual(deriveResult, 0)

        let message: [UInt8] = Array("test message".utf8)
        let context: [UInt8] = Array("my context".utf8)

        // Sign with context
        var signature = [UInt8](repeating: 0, count: 4627)
        var signatureLen: Int = 4627
        let signResult = go_signMLDSA87(
            seed,
            32,
            message,
            message.count,
            context,
            context.count,
            &signature,
            &signatureLen
        )
        XCTAssertEqual(signResult, 0, "Signing with context should succeed")

        // Verify with correct context
        let verifyResult = go_verifyMLDSA87(
            publicKey,
            2592,
            message,
            message.count,
            context,
            context.count,
            signature,
            signatureLen
        )
        XCTAssertEqual(verifyResult, 0, "Verification with correct context should succeed")

        // Verify with wrong context should fail
        let wrongContext: [UInt8] = Array("wrong context".utf8)
        let badVerifyResult = go_verifyMLDSA87(
            publicKey,
            2592,
            message,
            message.count,
            wrongContext,
            wrongContext.count,
            signature,
            signatureLen
        )
        XCTAssertNotEqual(badVerifyResult, 0, "Verification with wrong context should fail")
    }

    @available(macOS 26.0, *)
    func testMLDSA87ValidatePublicKey() throws {
        var seed = [UInt8](repeating: 0, count: 32)
        let genResult = go_generateKeyMLDSA87(&seed, 32)
        XCTAssertEqual(genResult, 0)

        var publicKey = [UInt8](repeating: 0, count: 2592)
        let deriveResult = go_derivePublicKeyMLDSA87(seed, 32, &publicKey, 2592)
        XCTAssertEqual(deriveResult, 0)

        let validResult = go_validatePublicKeyMLDSA87(publicKey, 2592)
        XCTAssertEqual(validResult, 0, "Valid public key should pass validation")
    }

    @available(macOS 26.0, *)
    func testMLDSA87UniqueKeys() throws {
        var seed1 = [UInt8](repeating: 0, count: 32)
        let gen1 = go_generateKeyMLDSA87(&seed1, 32)
        XCTAssertEqual(gen1, 0)

        var seed2 = [UInt8](repeating: 0, count: 32)
        let gen2 = go_generateKeyMLDSA87(&seed2, 32)
        XCTAssertEqual(gen2, 0)

        XCTAssertNotEqual(seed1, seed2, "Two generated seeds should differ")
    }

    // MARK: - Cross-Variant Tests

    @available(macOS 26.0, *)
    func testMLDSACrossVariantSizes() throws {
        // ML-DSA-65 should have smaller keys and signatures than ML-DSA-87
        XCTAssertLessThan(1952, 2592, "ML-DSA-65 public key should be smaller than ML-DSA-87")
        XCTAssertLessThan(3309, 4627, "ML-DSA-65 signature should be smaller than ML-DSA-87")

        // Both variants should generate seeds of the same size
        var seed65 = [UInt8](repeating: 0, count: 32)
        let gen65 = go_generateKeyMLDSA65(&seed65, 32)
        XCTAssertEqual(gen65, 0, "ML-DSA-65 seed generation should succeed")

        var seed87 = [UInt8](repeating: 0, count: 32)
        let gen87 = go_generateKeyMLDSA87(&seed87, 32)
        XCTAssertEqual(gen87, 0, "ML-DSA-87 seed generation should succeed")

        XCTAssertEqual(seed65.count, seed87.count, "Both variants should have same seed size")
    }

    // MARK: - Cross-Key Verification Tests

    @available(macOS 26.0, *)
    func testMLDSACrossKeyVerificationFails() throws {
        // Sign with one key, verify with another — should fail
        var seed1 = [UInt8](repeating: 0, count: 32)
        let gen1 = go_generateKeyMLDSA65(&seed1, 32)
        XCTAssertEqual(gen1, 0)

        var seed2 = [UInt8](repeating: 0, count: 32)
        let gen2 = go_generateKeyMLDSA65(&seed2, 32)
        XCTAssertEqual(gen2, 0)

        var publicKey2 = [UInt8](repeating: 0, count: 1952)
        let d2 = go_derivePublicKeyMLDSA65(seed2, 32, &publicKey2, 1952)
        XCTAssertEqual(d2, 0)

        // Sign with seed1
        let message: [UInt8] = Array("cross-key test".utf8)
        var signature = [UInt8](repeating: 0, count: 3309)
        var signatureLen: Int = 3309
        let emptyContext: [UInt8] = []
        let signResult = go_signMLDSA65(
            seed1,
            32,
            message,
            message.count,
            emptyContext,
            0,
            &signature,
            &signatureLen
        )
        XCTAssertEqual(signResult, 0)

        // Verify with publicKey2 — should fail
        let verifyResult = go_verifyMLDSA65(
            publicKey2,
            1952,
            message,
            message.count,
            emptyContext,
            0,
            signature,
            signatureLen
        )
        XCTAssertNotEqual(verifyResult, 0, "Verification with wrong key should fail")
    }

    #endif
}
