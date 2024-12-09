// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest

@testable import CryptoKitSrc

final class GCMTests: XCTestCase {
    func testEncryptAESGCM() {
        let key = "12345678901234567890123456789012".data(using: .utf8)!
        let data = "Hello, World!".data(using: .utf8)!
        let nonce = "123456789012".data(using: .utf8)!
        let aad = "AdditionalData".data(using: .utf8)!

        var cipherText = [UInt8](repeating: 0, count: data.count)
        var tag = [UInt8](repeating: 0, count: 16)

        let result = encryptAESGCM(
            keyPointer: (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count),
            keyLength: key.count,
            dataPointer: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count),
            dataLength: data.count,
            noncePointer: (nonce as NSData).bytes.bindMemory(to: UInt8.self, capacity: nonce.count),
            nonceLength: nonce.count,
            aadPointer: (aad as NSData).bytes.bindMemory(to: UInt8.self, capacity: aad.count),
            aadLength: aad.count,
            cipherTextPointer: &cipherText,
            cipherTextLength: cipherText.count,
            tagPointer: &tag
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

        let encryptResult = encryptAESGCM(
            keyPointer: (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count),
            keyLength: key.count,
            dataPointer: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count),
            dataLength: data.count,
            noncePointer: (nonce as NSData).bytes.bindMemory(to: UInt8.self, capacity: nonce.count),
            nonceLength: nonce.count,
            aadPointer: (aad as NSData).bytes.bindMemory(to: UInt8.self, capacity: aad.count),
            aadLength: aad.count,
            cipherTextPointer: &cipherText,
            cipherTextLength: cipherText.count,
            tagPointer: &tag
        )

        XCTAssertEqual(encryptResult, 0)

        var decryptedData = [UInt8](repeating: 0, count: data.count)
        var decryptedDataLength = data.count

        let decryptResult = decryptAESGCM(
            keyPointer: (key as NSData).bytes.bindMemory(to: UInt8.self, capacity: key.count),
            keyLength: key.count,
            dataPointer: &cipherText,
            dataLength: cipherText.count,
            noncePointer: (nonce as NSData).bytes.bindMemory(to: UInt8.self, capacity: nonce.count),
            nonceLength: nonce.count,
            aadPointer: (aad as NSData).bytes.bindMemory(to: UInt8.self, capacity: aad.count),
            aadLength: aad.count,
            tagPointer: &tag,
            tagLength: tag.count,
            outPointer: &decryptedData,
            outLength: &decryptedDataLength
        )

        XCTAssertEqual(decryptResult, 0)
        XCTAssertEqual(decryptedDataLength, data.count)
        XCTAssertEqual(Data(decryptedData), data)
    }
}
