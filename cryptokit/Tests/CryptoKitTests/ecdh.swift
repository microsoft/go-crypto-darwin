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
        let keySize = 32

        // 1. Generate Key
        var keyBuffer = [UInt8](repeating: 0, count: 64)  // 32 priv + 32 pub
        let genResult = generateKeyX25519(keyPointer: &keyBuffer, keyPointerLen: 64)
        XCTAssertEqual(genResult, 0, "GenerateKeyX25519 failed")

        let privateKey = Array(keyBuffer[0..<32])
        let publicKey = Array(keyBuffer[32..<64])

        // 2. Derive Public Key from Private Key
        var deriveBuffer = [UInt8](repeating: 0, count: 64)
        // Copy private key to first 32 bytes
        for i in 0..<32 {
            deriveBuffer[i] = privateKey[i]
        }

        let deriveResult = go_publicKeyX25519(privKey: &deriveBuffer, seedLen: 64)
        XCTAssertEqual(deriveResult, 0, "PublicKeyX25519 failed")

        let derivedPublicKey = Array(deriveBuffer[32..<64])
        XCTAssertEqual(publicKey, derivedPublicKey, "Derived X25519 public key does not match generated public key")

        // 3. Shared Secret
        // Generate Bob's key
        var bobKeyBuffer = [UInt8](repeating: 0, count: 64)
        _ = generateKeyX25519(keyPointer: &bobKeyBuffer, keyPointerLen: 64)
        let bobPrivateKey = Array(bobKeyBuffer[0..<32])
        let bobPublicKey = Array(bobKeyBuffer[32..<64])

        var aliceSharedSecret = [UInt8](repeating: 0, count: keySize)
        let aliceResult = x25519(
            privateKeyPointer: privateKey,
            privateKeyLen: 32,
            publicKeyPointer: bobPublicKey,
            publicKeyLen: 32,
            sharedSecretPointer: &aliceSharedSecret,
            sharedSecretLen: 32
        )
        XCTAssertEqual(aliceResult, 0, "Alice X25519 failed")

        var bobSharedSecret = [UInt8](repeating: 0, count: keySize)
        let bobResult = x25519(
            privateKeyPointer: bobPrivateKey,
            privateKeyLen: 32,
            publicKeyPointer: publicKey,
            publicKeyLen: 32,
            sharedSecretPointer: &bobSharedSecret,
            sharedSecretLen: 32
        )
        XCTAssertEqual(bobResult, 0, "Bob X25519 failed")

        XCTAssertEqual(aliceSharedSecret, bobSharedSecret, "X25519 shared secrets do not match")
    }

    func testCurve(curveID: Int32, keySize: Int) {
        let pubKeySize = 1 + keySize * 2

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
