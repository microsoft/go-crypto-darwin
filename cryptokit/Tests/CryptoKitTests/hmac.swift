// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest

@testable import CryptoKitSrc

class HMACTests: XCTestCase {
    func testHMAC_MD5() {
        runHMACTest(hashFunction: 1, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA1() {
        runHMACTest(hashFunction: 2, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA256() {
        runHMACTest(hashFunction: 3, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA384() {
        runHMACTest(hashFunction: 4, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA512() {
        runHMACTest(hashFunction: 5, key: "secret", message: "Hello, world!")
    }

    private func runHMACTest(hashFunction: Int32, key: String, message: String) {
        let keyData = key.data(using: .utf8)!
        let messageData = message.data(using: .utf8)!

        let keyPointer = keyData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }
        let hmacPointer = initHMAC(hashFunction, keyPointer, keyData.count)

        let messagePointer = messageData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }
        updateHMAC(hashFunction, hmacPointer, messagePointer, messageData.count)

        let outputSize = getHMACOutputSize(hashFunction)
        var output = [UInt8](repeating: 0, count: outputSize)
        finalizeHMAC(hashFunction, hmacPointer, &output)

        freeHMAC(hashFunction, hmacPointer)

        XCTAssertFalse(output.allSatisfy { $0 == 0 }, "HMAC output should not be all zeros")
    }

    private func getHMACOutputSize(_ hashFunction: Int32) -> Int {
        switch hashFunction {
        case 1: return 16  // MD5
        case 2: return 20  // SHA-1
        case 3: return 32  // SHA-256
        case 4: return 48  // SHA-384
        case 5: return 64  // SHA-512
        default: fatalError("Unsupported hash function")
        }
    }
}
