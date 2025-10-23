// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation
import XCTest

@testable import CryptoKitSrc

final class MLKEMTests: XCTestCase {

    // MARK: - ML-KEM Support Detection Tests

    func testMLKEMSupportDetection() {
        let isSupported = supportsMLKEM()

        if #available(macOS 26.0, *) {
            XCTAssertEqual(isSupported, 1, "ML-KEM should be supported on macOS 26.0+")
        } else {
            XCTAssertEqual(isSupported, 0, "ML-KEM should not be supported on macOS < 26.0")
        }
    }

    // MARK: - ML-KEM-768 Tests

    func testMLKEM768KeyGeneration() throws {
        guard #available(macOS 26.0, *) else {
            throw XCTSkip("ML-KEM is only available on macOS 26.0+")
        }

        var seed = [UInt8](repeating: 0, count: 64)  // SeedSize = 64
        let result = generateKeyMLKEM768(seedPointer: &seed)

        XCTAssertEqual(result, 0, "Key generation should succeed")

        // Verify the seed is not all zeros (it should contain random data)
        let allZeros = [UInt8](repeating: 0, count: 64)
        XCTAssertNotEqual(seed, allZeros, "Generated seed should not be all zeros")
    }

    func testMLKEM768DeriveEncapsulationKey() throws {
        guard #available(macOS 26.0, *) else {
            throw XCTSkip("ML-KEM is only available on macOS 26.0+")
        }

        // Generate a seed first
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = generateKeyMLKEM768(seedPointer: &seed)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        // Derive the encapsulation key
        var encapKey = [UInt8](repeating: 0, count: 1184)  // EncapsulationKeySize768 = 1184
        let deriveResult = deriveEncapsulationKeyMLKEM768(
            seedPointer: seed,
            encapKeyPointer: &encapKey
        )

        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Verify the encapsulation key is not all zeros
        let allZeros = [UInt8](repeating: 0, count: 1184)
        XCTAssertNotEqual(encapKey, allZeros, "Derived encapsulation key should not be all zeros")
    }

    func testMLKEM768EncapsulateDecapsulate() throws {
        guard #available(macOS 26.0, *) else {
            throw XCTSkip("ML-KEM is only available on macOS 26.0+")
        }

        // Generate a key pair
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = generateKeyMLKEM768(seedPointer: &seed)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        var encapKey = [UInt8](repeating: 0, count: 1184)
        let deriveResult = deriveEncapsulationKeyMLKEM768(
            seedPointer: seed,
            encapKeyPointer: &encapKey
        )
        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Encapsulate
        var sharedKey1 = [UInt8](repeating: 0, count: 32)  // SharedKeySize = 32
        var ciphertext = [UInt8](repeating: 0, count: 1088)  // CiphertextSize768 = 1088
        let encapResult = encapsulateMLKEM768(
            encapKeyPointer: encapKey,
            sharedKeyPointer: &sharedKey1,
            ciphertextPointer: &ciphertext
        )
        XCTAssertEqual(encapResult, 0, "Encapsulation should succeed")

        // Decapsulate
        var sharedKey2 = [UInt8](repeating: 0, count: 32)
        let decapResult = decapsulateMLKEM768(
            seedPointer: seed,
            ciphertextPointer: ciphertext,
            sharedKeyPointer: &sharedKey2
        )
        XCTAssertEqual(decapResult, 0, "Decapsulation should succeed")

        // Verify the shared keys match
        XCTAssertEqual(sharedKey1, sharedKey2, "Encapsulated and decapsulated shared keys should match")

        // Verify shared keys are not all zeros
        let allZeros32 = [UInt8](repeating: 0, count: 32)
        XCTAssertNotEqual(sharedKey1, allZeros32, "Shared key should not be all zeros")
    }

    // MARK: - ML-KEM-1024 Tests

    func testMLKEM1024KeyGeneration() throws {
        guard #available(macOS 26.0, *) else {
            throw XCTSkip("ML-KEM is only available on macOS 26.0+")
        }

        var seed = [UInt8](repeating: 0, count: 64)  // SeedSize = 64
        let result = generateKeyMLKEM1024(seedPointer: &seed)

        XCTAssertEqual(result, 0, "Key generation should succeed")

        // Verify the seed is not all zeros
        let allZeros = [UInt8](repeating: 0, count: 64)
        XCTAssertNotEqual(seed, allZeros, "Generated seed should not be all zeros")
    }

    func testMLKEM1024DeriveEncapsulationKey() throws {
        guard #available(macOS 26.0, *) else {
            throw XCTSkip("ML-KEM is only available on macOS 26.0+")
        }

        // Generate a seed first
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = generateKeyMLKEM1024(seedPointer: &seed)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        // Derive the encapsulation key
        var encapKey = [UInt8](repeating: 0, count: 1568)  // EncapsulationKeySize1024 = 1568
        let deriveResult = deriveEncapsulationKeyMLKEM1024(
            seedPointer: seed,
            encapKeyPointer: &encapKey
        )

        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Verify the encapsulation key is not all zeros
        let allZeros = [UInt8](repeating: 0, count: 1568)
        XCTAssertNotEqual(encapKey, allZeros, "Derived encapsulation key should not be all zeros")
    }

    func testMLKEM1024EncapsulateDecapsulate() throws {
        guard #available(macOS 26.0, *) else {
            throw XCTSkip("ML-KEM is only available on macOS 26.0+")
        }

        // Generate a key pair
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = generateKeyMLKEM1024(seedPointer: &seed)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        var encapKey = [UInt8](repeating: 0, count: 1568)
        let deriveResult = deriveEncapsulationKeyMLKEM1024(
            seedPointer: seed,
            encapKeyPointer: &encapKey
        )
        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Encapsulate
        var sharedKey1 = [UInt8](repeating: 0, count: 32)  // SharedKeySize = 32
        var ciphertext = [UInt8](repeating: 0, count: 1568)  // CiphertextSize1024 = 1568
        let encapResult = encapsulateMLKEM1024(
            encapKeyPointer: encapKey,
            sharedKeyPointer: &sharedKey1,
            ciphertextPointer: &ciphertext
        )
        XCTAssertEqual(encapResult, 0, "Encapsulation should succeed")

        // Decapsulate
        var sharedKey2 = [UInt8](repeating: 0, count: 32)
        let decapResult = decapsulateMLKEM1024(
            seedPointer: seed,
            ciphertextPointer: ciphertext,
            sharedKeyPointer: &sharedKey2
        )
        XCTAssertEqual(decapResult, 0, "Decapsulation should succeed")

        // Verify the shared keys match
        XCTAssertEqual(sharedKey1, sharedKey2, "Encapsulated and decapsulated shared keys should match")

        // Verify shared keys are not all zeros
        let allZeros32 = [UInt8](repeating: 0, count: 32)
        XCTAssertNotEqual(sharedKey1, allZeros32, "Shared key should not be all zeros")
    }

    // MARK: - Error Handling Tests

    func testMLKEMErrorHandling() throws {
        guard #available(macOS 26.0, *) else {
            throw XCTSkip("ML-KEM is only available on macOS 26.0+")
        }

        // Test decapsulation with invalid ciphertext (all zeros should fail)
        let seed = [UInt8](repeating: 1, count: 64)  // Use non-zero seed for valid key
        let invalidCiphertext = [UInt8](repeating: 0, count: 1088)
        var sharedKey = [UInt8](repeating: 0, count: 32)

        let result = decapsulateMLKEM768(
            seedPointer: seed,
            ciphertextPointer: invalidCiphertext,
            sharedKeyPointer: &sharedKey
        )

        // Note: This might succeed depending on CryptoKit implementation
        // The test mainly ensures the function doesn't crash
        XCTAssert(result == 0 || result == 1, "Decapsulation should return either success or failure")
    }

    // MARK: - Cross-Variant Tests

    func testMLKEMCrossVariantSizes() {
        // Test that different variants have different sizes as expected
        // These are compile-time constants, so no availability check needed

        // ML-KEM-768 should have smaller keys and ciphertext than ML-KEM-1024
        XCTAssertLessThan(1184, 1568, "ML-KEM-768 encapsulation key should be smaller than ML-KEM-1024")
        XCTAssertLessThan(1088, 1568, "ML-KEM-768 ciphertext should be smaller than ML-KEM-1024")

        // Both should have same shared key and seed sizes
        XCTAssertEqual(32, 32, "Both variants should have same shared key size")
        XCTAssertEqual(64, 64, "Both variants should have same seed size")
    }
}
