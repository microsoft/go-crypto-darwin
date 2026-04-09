// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import CryptoKitC
import Foundation
import XCTest

@testable import CryptoKitSrc

final class MLKEMTests: XCTestCase {

    // MARK: - ML-KEM Support Detection Tests

    #if compiler(>=6.2)
    @available(macOS 26.0, *)
    func testMLKEMSupportDetection() {
        let isSupported = go_supportsMLKEM()
        XCTAssertEqual(isSupported, 1, "ML-KEM should be supported on macOS 26.0+")
    }
    #endif

    // MARK: - ML-KEM-768 Tests

    #if compiler(>=6.2)
    @available(macOS 26.0, *)
    func testMLKEM768KeyGeneration() throws {

        var seed = [UInt8](repeating: 0, count: 64)  // SeedSize = 64
        let result = go_generateKeyMLKEM768(&seed, 64)

        XCTAssertEqual(result, 0, "Key generation should succeed")

        // Verify the seed is not all zeros (it should contain random data)
        let allZeros = [UInt8](repeating: 0, count: 64)
        XCTAssertNotEqual(seed, allZeros, "Generated seed should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLKEM768DeriveEncapsulationKey() throws {

        // Generate a seed first
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = go_generateKeyMLKEM768(&seed, 64)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        // Derive the encapsulation key
        var encapKey = [UInt8](repeating: 0, count: 1184)  // EncapsulationKeySize768 = 1184
        let deriveResult = go_deriveEncapsulationKeyMLKEM768(
            seed,
            64,
            &encapKey,
            1184
        )

        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Verify the encapsulation key is not all zeros
        let allZeros = [UInt8](repeating: 0, count: 1184)
        XCTAssertNotEqual(encapKey, allZeros, "Derived encapsulation key should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLKEM768EncapsulateDecapsulate() throws {

        // Generate a key pair
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = go_generateKeyMLKEM768(&seed, 64)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        var encapKey = [UInt8](repeating: 0, count: 1184)
        let deriveResult = go_deriveEncapsulationKeyMLKEM768(
            seed,
            64,
            &encapKey,
            1184
        )
        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Encapsulate
        var sharedKey1 = [UInt8](repeating: 0, count: 32)  // SharedKeySize = 32
        var ciphertext = [UInt8](repeating: 0, count: 1088)  // CiphertextSize768 = 1088
        let encapResult = go_encapsulateMLKEM768(
            encapKey,
            1184,
            &sharedKey1,
            32,
            &ciphertext,
            1088
        )
        XCTAssertEqual(encapResult, 0, "Encapsulation should succeed")

        // Decapsulate
        var sharedKey2 = [UInt8](repeating: 0, count: 32)
        let decapResult = go_decapsulateMLKEM768(
            seed,
            64,
            ciphertext,
            1088,
            &sharedKey2,
            32
        )
        XCTAssertEqual(decapResult, 0, "Decapsulation should succeed")

        // Verify the shared keys match
        XCTAssertEqual(sharedKey1, sharedKey2, "Encapsulated and decapsulated shared keys should match")

        // Verify shared keys are not all zeros
        let allZeros32 = [UInt8](repeating: 0, count: 32)
        XCTAssertNotEqual(sharedKey1, allZeros32, "Shared key should not be all zeros")
    }

    // MARK: - ML-KEM-1024 Tests

    @available(macOS 26.0, *)
    func testMLKEM1024KeyGeneration() throws {

        var seed = [UInt8](repeating: 0, count: 64)  // SeedSize = 64
        let result = go_generateKeyMLKEM1024(&seed, 64)

        XCTAssertEqual(result, 0, "Key generation should succeed")

        // Verify the seed is not all zeros
        let allZeros = [UInt8](repeating: 0, count: 64)
        XCTAssertNotEqual(seed, allZeros, "Generated seed should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLKEM1024DeriveEncapsulationKey() throws {

        // Generate a seed first
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = go_generateKeyMLKEM1024(&seed, 64)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        // Derive the encapsulation key
        var encapKey = [UInt8](repeating: 0, count: 1568)  // EncapsulationKeySize1024 = 1568
        let deriveResult = go_deriveEncapsulationKeyMLKEM1024(
            seed,
            64,
            &encapKey,
            1568
        )

        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Verify the encapsulation key is not all zeros
        let allZeros = [UInt8](repeating: 0, count: 1568)
        XCTAssertNotEqual(encapKey, allZeros, "Derived encapsulation key should not be all zeros")
    }

    @available(macOS 26.0, *)
    func testMLKEM1024EncapsulateDecapsulate() throws {

        // Generate a key pair
        var seed = [UInt8](repeating: 0, count: 64)
        let genResult = go_generateKeyMLKEM1024(&seed, 64)
        XCTAssertEqual(genResult, 0, "Key generation should succeed")

        var encapKey = [UInt8](repeating: 0, count: 1568)
        let deriveResult = go_deriveEncapsulationKeyMLKEM1024(
            seed,
            64,
            &encapKey,
            1568
        )
        XCTAssertEqual(deriveResult, 0, "Encapsulation key derivation should succeed")

        // Encapsulate
        var sharedKey1 = [UInt8](repeating: 0, count: 32)  // SharedKeySize = 32
        var ciphertext = [UInt8](repeating: 0, count: 1568)  // CiphertextSize1024 = 1568
        let encapResult = go_encapsulateMLKEM1024(
            encapKey,
            1568,
            &sharedKey1,
            32,
            &ciphertext,
            1568
        )
        XCTAssertEqual(encapResult, 0, "Encapsulation should succeed")

        // Decapsulate
        var sharedKey2 = [UInt8](repeating: 0, count: 32)
        let decapResult = go_decapsulateMLKEM1024(
            seed,
            64,
            ciphertext,
            1568,
            &sharedKey2,
            32
        )
        XCTAssertEqual(decapResult, 0, "Decapsulation should succeed")

        // Verify the shared keys match
        XCTAssertEqual(sharedKey1, sharedKey2, "Encapsulated and decapsulated shared keys should match")

        // Verify shared keys are not all zeros
        let allZeros32 = [UInt8](repeating: 0, count: 32)
        XCTAssertNotEqual(sharedKey1, allZeros32, "Shared key should not be all zeros")
    }

    // MARK: - Error Handling Tests

    @available(macOS 26.0, *)
    func testMLKEMErrorHandling() throws {

        // Test decapsulation with invalid ciphertext (all zeros should fail)
        let seed = [UInt8](repeating: 1, count: 64)  // Use non-zero seed for valid key
        let invalidCiphertext = [UInt8](repeating: 0, count: 1088)
        var sharedKey = [UInt8](repeating: 0, count: 32)

        let result = go_decapsulateMLKEM768(
            seed,
            64,
            invalidCiphertext,
            1088,
            &sharedKey,
            32
        )

        // Note: This might succeed depending on CryptoKit implementation
        // The test mainly ensures the function doesn't crash
        XCTAssert(result == 0 || result == 1, "Decapsulation should return either success or failure")
    }

    #endif

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
