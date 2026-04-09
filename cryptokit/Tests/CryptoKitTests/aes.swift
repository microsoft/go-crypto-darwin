// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest

@testable import CryptoKitSrc
import CryptoKitC

final class GCMTests: XCTestCase {
    func testEncryptAESGCM() {
        let key = "12345678901234567890123456789012".data(using: .utf8)!
        let data = "Hello, World!".data(using: .utf8)!
        let nonce = "123456789012".data(using: .utf8)!
        let aad = "AdditionalData".data(using: .utf8)!

        var cipherText = [UInt8](repeating: 0, count: data.count)
        var tag = [UInt8](repeating: 0, count: 16)

        let result = go_encryptAESGCM(
            (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count),
            key.count,
            (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count),
            data.count,
            (nonce as NSData).bytes.bindMemory(to: UInt8.self, capacity: nonce.count),
            nonce.count,
            (aad as NSData).bytes.bindMemory(to: UInt8.self, capacity: aad.count),
            aad.count,
            &cipherText,
            cipherText.count,
            &tag
        )

        XCTAssertEqual(result, 0)
        XCTAssertFalse(cipherText.isEmpty)
        XCTAssertFalse(tag.isEmpty)
    }

    func testDecryptAESGCM() {
        let key = "12345678901234567890123456789012".data(using: .utf8)!
        let data = "Hello, World!".data(using: .utf8)!
        let nonce = "123456789012".data(using: .utf8)!
        let aad = "AdditionalData".data(using: .utf8)!

        var cipherText = [UInt8](repeating: 0, count: data.count)
        var tag = [UInt8](repeating: 0, count: 16)

        let encryptResult = go_encryptAESGCM(
            (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count),
            key.count,
            (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count),
            data.count,
            (nonce as NSData).bytes.bindMemory(to: UInt8.self, capacity: nonce.count),
            nonce.count,
            (aad as NSData).bytes.bindMemory(to: UInt8.self, capacity: aad.count),
            aad.count,
            &cipherText,
            cipherText.count,
            &tag
        )

        XCTAssertEqual(encryptResult, 0)

        var decryptedData = [UInt8](repeating: 0, count: data.count)
        var decryptedDataLength = data.count

        let decryptResult = go_decryptAESGCM(
            (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count),
            key.count,
            &cipherText,
            cipherText.count,
            (nonce as NSData).bytes.bindMemory(to: UInt8.self, capacity: nonce.count),
            nonce.count,
            (aad as NSData).bytes.bindMemory(to: UInt8.self, capacity: aad.count),
            aad.count,
            &tag,
            tag.count,
            &decryptedData,
            &decryptedDataLength
        )

        XCTAssertEqual(decryptResult, 0)
        XCTAssertEqual(decryptedDataLength, data.count)
        XCTAssertEqual(Data(decryptedData), data)
    }
}
