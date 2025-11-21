// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest

@testable import CryptoKitSrc

final class ECDSACryptoTests: XCTestCase {

    func testP256() {
        testCurve(curveID: 1, keySize: 32)
    }

    func testP384() {
        testCurve(curveID: 2, keySize: 48)
    }

    func testP521() {
        testCurve(curveID: 3, keySize: 66)
    }

    func testCurve(curveID: Int32, keySize: Int) {
        // 1. Generate Key
        var x = [UInt8](repeating: 0, count: keySize)
        var y = [UInt8](repeating: 0, count: keySize)
        var d = [UInt8](repeating: 0, count: keySize)
        
        let genResult = generateKeyECDSA(
            curveID: curveID,
            xPointer: &x,
            xLen: keySize,
            yPointer: &y,
            yLen: keySize,
            dPointer: &d,
            dLen: keySize
        )
        XCTAssertEqual(genResult, 0, "GenerateKeyECDSA failed for curve \(curveID)")
        
        // 2. Sign
        let message = "Hello, ECDSA!".data(using: .utf8)!
        var signature = [UInt8](repeating: 0, count: 256) // Max size
        var signatureLen = 0
        
        let signResult = message.withUnsafeBytes { messagePointer in
            ecdsaSign(
                curveID: curveID,
                dPointer: &d,
                dLen: keySize,
                messagePointer: messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                messageLen: message.count,
                signaturePointer: &signature,
                signatureLen: &signatureLen
            )
        }
        XCTAssertEqual(signResult, 0, "ECDSASign failed for curve \(curveID)")
        XCTAssertGreaterThan(signatureLen, 0, "Signature length should be greater than 0")
        
        // 3. Verify
        let verifyResult = message.withUnsafeBytes { messagePointer in
            ecdsaVerify(
                curveID: curveID,
                xPointer: &x,
                xLen: Int32(keySize),
                yPointer: &y,
                yLen: Int32(keySize),
                messagePointer: messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                messageLen: Int32(message.count),
                signaturePointer: &signature,
                signatureLen: Int32(signatureLen)
            )
        }
        XCTAssertEqual(verifyResult, 1, "ECDSAVerify failed for curve \(curveID)")
        
        // 4. Verify with wrong message
        let wrongMessage = "Wrong message".data(using: .utf8)!
        let verifyWrongResult = wrongMessage.withUnsafeBytes { messagePointer in
            ecdsaVerify(
                curveID: curveID,
                xPointer: &x,
                xLen: Int32(keySize),
                yPointer: &y,
                yLen: Int32(keySize),
                messagePointer: messagePointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                messageLen: Int32(wrongMessage.count),
                signaturePointer: &signature,
                signatureLen: Int32(signatureLen)
            )
        }
        XCTAssertEqual(verifyWrongResult, 0, "ECDSAVerify should fail for wrong message")
    }
}
