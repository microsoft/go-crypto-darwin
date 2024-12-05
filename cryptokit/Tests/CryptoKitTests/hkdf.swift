// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest
@testable import CryptoKitSrc

class HKDFTests: XCTestCase {

    func testExtractHKDF_SHA256() {
        let secret = "TestSecret".data(using: .utf8)!
        let salt = "TestSalt".data(using: .utf8)!
        var prk = [UInt8](repeating: 0, count: 32) // Expected size for SHA256 PRK

        let result = extractHKDF(
            hashFunction: 2, // SHA256
            secretPointer: Array(secret),
            secretLength: secret.count,
            saltPointer: Array(salt),
            saltLength: salt.count,
            prkPointer: &prk,
            prkLength: prk.count
        )

        XCTAssertEqual(result, 0, "extractHKDF failed with SHA256")
        XCTAssertFalse(prk.allSatisfy { $0 == 0 }, "PRK buffer was not populated")
    }

    func testExtractHKDF_UnsupportedHash() {
        let secret = "TestSecret".data(using: .utf8)!
        let salt = "TestSalt".data(using: .utf8)!
        var prk = [UInt8](repeating: 0, count: 32)

        let result = extractHKDF(
            hashFunction: 0, // Unsupported hash function
            secretPointer: Array(secret),
            secretLength: secret.count,
            saltPointer: Array(salt),
            saltLength: salt.count,
            prkPointer: &prk,
            prkLength: prk.count
        )

        XCTAssertEqual(result, -1, "extractHKDF should fail for unsupported hash function")
    }

    func testExpandHKDF_SHA512() {
        let prk = Data(repeating: 0xAA, count: 64) // Mocked PRK for SHA512
        let info = "TestInfo".data(using: .utf8)!
        var derivedKey = [UInt8](repeating: 0, count: 64) // Derived key size

        let result = expandHKDF(
            hashFunction: 4, // SHA512
            prkPointer: Array(prk),
            prkLength: prk.count,
            infoPointer: Array(info),
            infoLength: info.count,
            derivedKeyPointer: &derivedKey,
            derivedKeyLength: derivedKey.count
        )

        XCTAssertEqual(result, 0, "expandHKDF failed with SHA512")
        XCTAssertFalse(derivedKey.allSatisfy { $0 == 0 }, "Derived key buffer was not populated")
    }

    func testExpandHKDF_UnsupportedHash() {
        let prk = Data(repeating: 0xAA, count: 32)
        let info = "TestInfo".data(using: .utf8)!
        var derivedKey = [UInt8](repeating: 0, count: 32)

        let result = expandHKDF(
            hashFunction: 0, // Unsupported hash function
            prkPointer: Array(prk),
            prkLength: prk.count,
            infoPointer: Array(info),
            infoLength: info.count,
            derivedKeyPointer: &derivedKey,
            derivedKeyLength: derivedKey.count
        )

        XCTAssertEqual(result, -1, "expandHKDF should fail for unsupported hash function")
    }
}
