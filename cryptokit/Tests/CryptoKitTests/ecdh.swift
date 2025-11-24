// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest

@testable import CryptoKitSrc

final class ECDHCryptoTests: XCTestCase {

    func testP256() {
        testCurve(curveID: 1, keySize: 32)
    }

    func testP384() {
        testCurve(curveID: 2, keySize: 48)
    }

    func testP521() {
        testCurve(curveID: 3, keySize: 66)
    }

    func testX25519() {
        testCurve(curveID: 0, keySize: 32)
    }

    func testCurve(curveID: Int32, keySize: Int) {
        let pubKeySize = (curveID == 0) ? keySize : (1 + keySize * 2)

        // 1. Generate Key
        var privateKey = [UInt8](repeating: 0, count: keySize)
        var publicKey = [UInt8](repeating: 0, count: pubKeySize)

        let genResult = generateKeyECDH(
            curveID: curveID,
            privateKeyPointer: &privateKey,
            privateKeyLen: keySize,
            publicKeyPointer: &publicKey,
            publicKeyLen: pubKeySize
        )
        XCTAssertEqual(genResult, 0, "GenerateKeyECDH failed for curve \(curveID)")

        // 2. Validate Keys
        let validPriv = validatePrivateKeyECDH(curveID: curveID, privateKeyPointer: &privateKey, privateKeyLen: keySize)
        XCTAssertEqual(validPriv, 0, "ValidatePrivateKeyECDH failed for curve \(curveID)")

        let validPub = validatePublicKeyECDH(curveID: curveID, publicKeyPointer: &publicKey, publicKeyLen: pubKeySize)
        XCTAssertEqual(validPub, 0, "ValidatePublicKeyECDH failed for curve \(curveID)")

        // 3. Derive Public Key from Private Key
        var derivedPublicKey = [UInt8](repeating: 0, count: pubKeySize)
        let deriveResult = publicKeyFromPrivateECDH(
            curveID: curveID,
            privateKeyPointer: &privateKey,
            privateKeyLen: keySize,
            publicKeyPointer: &derivedPublicKey,
            publicKeyLen: pubKeySize
        )
        XCTAssertEqual(deriveResult, 0, "PublicKeyFromPrivateECDH failed for curve \(curveID)")
        XCTAssertEqual(
            publicKey,
            derivedPublicKey,
            "Derived public key does not match generated public key for curve \(curveID)"
        )

        // 4. Shared Secret (Self-exchange for simplicity, or generate another pair)
        // Let's generate a second pair for Alice/Bob exchange
        var bobPrivateKey = [UInt8](repeating: 0, count: keySize)
        var bobPublicKey = [UInt8](repeating: 0, count: pubKeySize)
        _ = generateKeyECDH(
            curveID: curveID,
            privateKeyPointer: &bobPrivateKey,
            privateKeyLen: keySize,
            publicKeyPointer: &bobPublicKey,
            publicKeyLen: pubKeySize
        )

        var aliceSharedSecret = [UInt8](repeating: 0, count: keySize)
        let aliceResult = ecdhSharedSecret(
            curveID: curveID,
            privateKeyPointer: &privateKey,
            privateKeyLen: keySize,
            publicKeyPointer: &bobPublicKey,
            publicKeyLen: pubKeySize,
            sharedSecretPointer: &aliceSharedSecret,
            sharedSecretLen: keySize
        )
        XCTAssertEqual(aliceResult, 0, "Alice ECDH failed for curve \(curveID)")

        var bobSharedSecret = [UInt8](repeating: 0, count: keySize)
        let bobResult = ecdhSharedSecret(
            curveID: curveID,
            privateKeyPointer: &bobPrivateKey,
            privateKeyLen: keySize,
            publicKeyPointer: &publicKey,
            publicKeyLen: pubKeySize,
            sharedSecretPointer: &bobSharedSecret,
            sharedSecretLen: keySize
        )
        XCTAssertEqual(bobResult, 0, "Bob ECDH failed for curve \(curveID)")

        XCTAssertEqual(aliceSharedSecret, bobSharedSecret, "Shared secrets do not match for curve \(curveID)")
    }
}
