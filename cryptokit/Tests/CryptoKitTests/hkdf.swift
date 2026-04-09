// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest

@testable import CryptoKitSrc
import CryptoKitC

final class HKDFTests: XCTestCase {
    func testExtractHKDF_SHA256() {
        let secret = "TestSecret".data(using: .utf8)!
        let salt = "TestSalt".data(using: .utf8)!
        var prk = [UInt8](repeating: 0, count: 32)  // Expected size for SHA256 PRK

        let result = go_extractHKDF(
            2,  // SHA256
            Array(secret),
            secret.count,
            Array(salt),
            salt.count,
            &prk,
            prk.count
        )

        XCTAssertEqual(result, 0, "extractHKDF failed with SHA256")
        XCTAssertFalse(prk.allSatisfy { $0 == 0 }, "PRK buffer was not populated")
    }

    func testExtractHKDF_UnsupportedHash() {
        let secret = "TestSecret".data(using: .utf8)!
        let salt = "TestSalt".data(using: .utf8)!
        var prk = [UInt8](repeating: 0, count: 32)

        let result = go_extractHKDF(
            0,  // Unsupported hash function
            Array(secret),
            secret.count,
            Array(salt),
            salt.count,
            &prk,
            prk.count
        )

        XCTAssertEqual(result, -1, "extractHKDF should fail for unsupported hash function")
    }

    func testExpandHKDF_SHA512() {
        let prk = Data(repeating: 0xAA, count: 64)  // Mocked PRK for SHA512
        let info = "TestInfo".data(using: .utf8)!
        var derivedKey = [UInt8](repeating: 0, count: 64)  // Derived key size

        let result = go_expandHKDF(
            4,  // SHA512
            Array(prk),
            prk.count,
            Array(info),
            info.count,
            &derivedKey,
            derivedKey.count
        )

        XCTAssertEqual(result, 0, "expandHKDF failed with SHA512")
        XCTAssertFalse(derivedKey.allSatisfy { $0 == 0 }, "Derived key buffer was not populated")
    }

    func testExpandHKDF_UnsupportedHash() {
        let prk = Data(repeating: 0xAA, count: 32)
        let info = "TestInfo".data(using: .utf8)!
        var derivedKey = [UInt8](repeating: 0, count: 32)

        let result = go_expandHKDF(
            0,  // Unsupported hash function
            Array(prk),
            prk.count,
            Array(info),
            info.count,
            &derivedKey,
            derivedKey.count
        )

        XCTAssertEqual(result, -1, "expandHKDF should fail for unsupported hash function")
    }
}
