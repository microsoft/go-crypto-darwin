// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

// Runtime feature detection for SHA3 (available on macOS 26+ only)
@_cdecl("go_supportsSHA3")
public func supportsSHA3() -> Int {
    if #available(macOS 26.0, *) {
        // SHA3 symbols are lazily bound, so if this returns true,
        // the runtime can safely call SHA3_* functions.
        return 1
    }
    return 0
}

@_cdecl("go_encryptAESGCM")
public func encryptAESGCM(
    keyPointer: UnsafePointer<UInt8>,
    keyLength: Int,
    dataPointer: UnsafePointer<UInt8>,
    dataLength: Int,
    noncePointer: UnsafePointer<UInt8>,
    nonceLength: Int,
    aadPointer: UnsafePointer<UInt8>,
    aadLength: Int,
    cipherTextPointer: UnsafeMutablePointer<UInt8>,
    cipherTextLength: Int,
    tagPointer: UnsafeMutablePointer<UInt8>
) -> Int {
    let keyData = Data(bytes: keyPointer, count: keyLength)
    let data = Data(bytes: dataPointer, count: dataLength)
    let nonce = try! AES.GCM.Nonce(data: Data(bytes: noncePointer, count: nonceLength))

    let symmetricKey = SymmetricKey(data: keyData)
    let aad: Data = Data(bytes: aadPointer, count: aadLength)

    do {
        let sealedBox: AES.GCM.SealedBox = try AES.GCM.seal(
            data,
            using: symmetricKey,
            nonce: nonce,
            authenticating: aad
        )
        let result = sealedBox.ciphertext
        result.copyBytes(to: cipherTextPointer, count: result.count)
        let resultTag = Data(sealedBox.tag)
        resultTag.copyBytes(to: tagPointer, count: sealedBox.tag.count)
        return 0
    } catch {
        return 1
    }
}

@_cdecl("go_decryptAESGCM")
public func decryptAESGCM(
    keyPointer: UnsafePointer<UInt8>,
    keyLength: Int,
    dataPointer: UnsafePointer<UInt8>,
    dataLength: Int,
    noncePointer: UnsafePointer<UInt8>,
    nonceLength: Int,
    aadPointer: UnsafePointer<UInt8>,
    aadLength: Int,
    tagPointer: UnsafePointer<UInt8>,
    tagLength: Int,
    outPointer: UnsafeMutablePointer<UInt8>,
    outLength: UnsafeMutablePointer<Int>
) -> Int {
    let keyData = Data(bytes: keyPointer, count: keyLength)
    let nonceData = Data(bytes: noncePointer, count: nonceLength)
    let symmetricKey: SymmetricKey = SymmetricKey(data: keyData)
    let nonce: AES.GCM.Nonce = try! AES.GCM.Nonce(data: nonceData)

    let tag: Data = Data(bytes: tagPointer, count: tagLength)
    let ciphertext = Data(bytes: dataPointer, count: dataLength)
    let aad = Data(bytes: aadPointer, count: aadLength)

    do {
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
        decryptedData.copyBytes(to: outPointer, count: decryptedData.count)
        outLength.pointee = decryptedData.count
        return 0
    } catch {
        return 1
    }
}

var publicKeySizeEd25519 = 32
var signatureSizeEd25519 = 64
var seedSizeEd25519 = 32

@_cdecl("go_generateKeyEd25519")
public func generateKeyEd25519(keyPointer: UnsafeMutablePointer<UInt8>) -> Void {
    // Generate a private key using CryptoKit
    let privateKey = Curve25519.Signing.PrivateKey()

    // Extract the raw representation of the private key
    let privateKeyData = privateKey.rawRepresentation

    // Allocate memory for the private key data and copy it
    privateKeyData.copyBytes(to: keyPointer, count: privateKeyData.count)
    privateKey.publicKey.rawRepresentation.copyBytes(to: keyPointer + publicKeySizeEd25519, count: publicKeySizeEd25519)
}

@_cdecl("go_newPrivateKeyEd25519FromSeed")
public func newPrivateKeyEd25519FromSeed(
    keyPointer: UnsafeMutablePointer<UInt8>,
    seedPointer: UnsafePointer<UInt8>
) -> Int {
    // Copy the seed into a Data object
    let seedData = Data(bytes: seedPointer, count: seedSizeEd25519)

    // Generate the private key from the seed
    let privateKey: Curve25519.Signing.PrivateKey
    do {
        privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedData)
    } catch {
        // Key generation failed
        return 1
    }

    // Extract the raw representation of the private key
    let privateKeyData = privateKey.rawRepresentation

    // Allocate memory for the private key data and copy it
    privateKeyData.copyBytes(to: keyPointer, count: privateKeyData.count)
    privateKey.publicKey.rawRepresentation.copyBytes(to: keyPointer + publicKeySizeEd25519, count: publicKeySizeEd25519)
    return 0
}

@_cdecl("go_newPublicKeyEd25519")
public func newPublicKeyEd25519(
    keyPointer: UnsafeMutablePointer<UInt8>,
    pubPointer: UnsafePointer<UInt8>
) -> Int {
    // Copy the public key bytes into a Data object
    let pubData = Data(bytes: pubPointer, count: seedSizeEd25519)

    do {
        // Create the public key from the raw representation
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubData)

        // Store the public key in memory and return the pointer
        publicKey.rawRepresentation.copyBytes(to: keyPointer, count: publicKeySizeEd25519)
        return 0
    } catch {
        // Failed to create the public key
        return 1
    }
}

@_cdecl("go_signEd25519")
public func signEd25519(
    privateKeyPointer: UnsafePointer<UInt8>,
    messagePointer: UnsafePointer<UInt8>?,
    messageLength: Int,
    sigBuffer: UnsafeMutablePointer<UInt8>?
) -> Int {
    guard let sigBuffer = sigBuffer else {
        return -1  // Invalid inputs
    }

    // Convert the raw private key back to the seed (32 bytes)
    let privateKeySeed = Data(bytes: privateKeyPointer, count: seedSizeEd25519)

    // Reconstruct the private key
    let privateKey: Curve25519.Signing.PrivateKey
    do {
        privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeySeed)
    } catch {
        return -2  // Failed to reconstruct private key
    }

    // Convert the message to Data
    let messageData: Data
    if let messagePointer = messagePointer, messageLength > 0 {
        messageData = Data(bytes: messagePointer, count: messageLength)
    } else {
        messageData = Data()  // Empty message
    }

    // Sign the message
    let signature: Data
    do {
        signature = try privateKey.signature(for: messageData)
    } catch {
        return -3  // Failed to sign the message
    }

    // Ensure the buffer is large enough
    guard signature.count == signatureSizeEd25519 else {
        return -4  // Buffer too small
    }

    // Copy the signature to the buffer
    signature.copyBytes(to: sigBuffer, count: signature.count)

    return signature.count  // Return the number of bytes written
}

@_cdecl("go_verifyEd25519")
public func verifyEd25519(
    publicKeyPointer: UnsafePointer<UInt8>,
    messagePointer: UnsafePointer<UInt8>?,
    messageLength: Int,
    sigPointer: UnsafePointer<UInt8>?
) -> Int {
    guard let sigPointer = sigPointer else {
        return -1  // Invalid inputs
    }

    // Convert the raw public key back to a Data object
    let publicKeyData = Data(bytes: publicKeyPointer, count: publicKeySizeEd25519)

    // Reconstruct the public key
    guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else {
        return -2  // Error: failed to reconstruct public key
    }

    // Convert the message and signature to Data
    let rawMessage: Data
    if let messagePointer = messagePointer, messageLength > 0 {
        rawMessage = Data(bytes: messagePointer, count: messageLength)
    } else {
        rawMessage = Data()  // Empty message
    }
    let signatureData = Data(bytes: sigPointer, count: signatureSizeEd25519)

    // Verify the signature
    let isValid = publicKey.isValidSignature(signatureData, for: rawMessage)
    return isValid ? 1 : 0  // Return 1 for valid, 0 for invalid
}

// X25519 Key Exchange (Now handled by generic ECDH functions with curveID=0)

// ECDH for P-256, P-384, P-521 using CryptoKit

// Helper function to determine key size based on curve
@_cdecl("go_getECDHKeySizeForCurve")
public func getECDHKeySizeForCurve(_ curveID: Int32) -> Int {
    switch curveID {
    case 0:  // X25519
        return 32
    case 1:  // P-256
        return 32
    case 2:  // P-384
        return 48
    case 3:  // P-521
        return 66
    default:
        return -1
    }
}

@_cdecl("go_generateKeyECDH")
public func generateKeyECDH(
    curveID: Int32,
    privateKeyPointer: UnsafeMutablePointer<UInt8>,
    privateKeyLen: Int,
    publicKeyPointer: UnsafeMutablePointer<UInt8>,
    publicKeyLen: Int
) -> Int {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0 else { return -1 }

    if curveID == 0 {
        // X25519
        guard privateKeyLen == keySize, publicKeyLen == keySize else { return -1 }
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        privateKeyData.copyBytes(to: privateKeyPointer, count: keySize)
        let publicKeyData = privateKey.publicKey.rawRepresentation
        publicKeyData.copyBytes(to: publicKeyPointer, count: keySize)
        return 0
    }

    guard privateKeyLen == keySize, publicKeyLen == 1 + keySize * 2 else {
        return -1  // Invalid key sizes
    }

    switch curveID {
    case 1:  // P-256
        let privateKey = P256.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        privateKeyData.copyBytes(to: privateKeyPointer, count: keySize)

        // Encode public key in uncompressed X9.63 format
        let publicKeyData = privateKey.publicKey.rawRepresentation
        publicKeyPointer[0] = 0x04  // Uncompressed format
        publicKeyData.copyBytes(to: publicKeyPointer + 1, count: keySize * 2)
        return 0

    case 2:  // P-384
        let privateKey = P384.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        privateKeyData.copyBytes(to: privateKeyPointer, count: keySize)

        // Encode public key in uncompressed X9.63 format
        let publicKeyData = privateKey.publicKey.rawRepresentation
        publicKeyPointer[0] = 0x04  // Uncompressed format
        publicKeyData.copyBytes(to: publicKeyPointer + 1, count: keySize * 2)
        return 0

    case 3:  // P-521
        let privateKey = P521.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        privateKeyData.copyBytes(to: privateKeyPointer, count: keySize)

        // Encode public key in uncompressed X9.63 format
        let publicKeyData = privateKey.publicKey.rawRepresentation
        publicKeyPointer[0] = 0x04  // Uncompressed format
        publicKeyData.copyBytes(to: publicKeyPointer + 1, count: keySize * 2)
        return 0

    default:
        return -1  // Unsupported curve
    }
}

@_cdecl("go_publicKeyFromPrivateECDH")
public func publicKeyFromPrivateECDH(
    curveID: Int32,
    privateKeyPointer: UnsafePointer<UInt8>,
    privateKeyLen: Int,
    publicKeyPointer: UnsafeMutablePointer<UInt8>,
    publicKeyLen: Int
) -> Int {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0 else { return -1 }

    if curveID == 0 {
        // X25519
        guard privateKeyLen == keySize, publicKeyLen == keySize else { return -1 }
        do {
            let privateKeyData = Data(bytes: privateKeyPointer, count: privateKeyLen)
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKeyData = privateKey.publicKey.rawRepresentation
            publicKeyData.copyBytes(to: publicKeyPointer, count: keySize)
            return 0
        } catch {
            return -2
        }
    }

    guard privateKeyLen == keySize, publicKeyLen == 1 + keySize * 2 else {
        return -1  // Invalid key sizes
    }

    do {
        let privateKeyData = Data(bytes: privateKeyPointer, count: privateKeyLen)

        switch curveID {
        case 1:  // P-256
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKeyData = privateKey.publicKey.rawRepresentation
            publicKeyPointer[0] = 0x04  // Uncompressed format
            publicKeyData.copyBytes(to: publicKeyPointer + 1, count: keySize * 2)
            return 0

        case 2:  // P-384
            let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKeyData = privateKey.publicKey.rawRepresentation
            publicKeyPointer[0] = 0x04  // Uncompressed format
            publicKeyData.copyBytes(to: publicKeyPointer + 1, count: keySize * 2)
            return 0

        case 3:  // P-521
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKeyData = privateKey.publicKey.rawRepresentation
            publicKeyPointer[0] = 0x04  // Uncompressed format
            publicKeyData.copyBytes(to: publicKeyPointer + 1, count: keySize * 2)
            return 0

        default:
            return -1  // Unsupported curve
        }
    } catch {
        return -2  // Error during key derivation
    }
}

@_cdecl("go_ecdhSharedSecret")
public func ecdhSharedSecret(
    curveID: Int32,
    privateKeyPointer: UnsafePointer<UInt8>,
    privateKeyLen: Int,
    publicKeyPointer: UnsafePointer<UInt8>,
    publicKeyLen: Int,
    sharedSecretPointer: UnsafeMutablePointer<UInt8>,
    sharedSecretLen: Int
) -> Int {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0 else { return -1 }

    if curveID == 0 {
        // X25519
        guard privateKeyLen == keySize, publicKeyLen == keySize else { return -1 }
        do {
            let privateKeyData = Data(bytes: privateKeyPointer, count: privateKeyLen)
            let publicKeyData = Data(bytes: publicKeyPointer, count: publicKeyLen)

            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)

            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            let sharedSecretBytes = sharedSecret.withUnsafeBytes { Data($0) }

            guard sharedSecretLen >= sharedSecretBytes.count else { return -3 }
            sharedSecretBytes.copyBytes(to: sharedSecretPointer, count: sharedSecretBytes.count)
            return 0
        } catch {
            return -2
        }
    }

    guard privateKeyLen == keySize, publicKeyLen == 1 + keySize * 2 else {
        return -1  // Invalid key sizes
    }

    do {
        let privateKeyData = Data(bytes: privateKeyPointer, count: privateKeyLen)
        let publicKeyData = Data(bytes: publicKeyPointer + 1, count: publicKeyLen - 1)

        switch curveID {
        case 1:  // P-256
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            let sharedSecretBytes = sharedSecret.withUnsafeBytes { Data($0) }
            guard sharedSecretLen >= sharedSecretBytes.count else { return -3 }
            sharedSecretBytes.copyBytes(to: sharedSecretPointer, count: sharedSecretBytes.count)
            return 0

        case 2:  // P-384
            let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKey = try P384.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            let sharedSecretBytes = sharedSecret.withUnsafeBytes { Data($0) }
            guard sharedSecretLen >= sharedSecretBytes.count else { return -3 }
            sharedSecretBytes.copyBytes(to: sharedSecretPointer, count: sharedSecretBytes.count)
            return 0

        case 3:  // P-521
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKey = try P521.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            let sharedSecretBytes = sharedSecret.withUnsafeBytes { Data($0) }
            guard sharedSecretLen >= sharedSecretBytes.count else { return -3 }
            sharedSecretBytes.copyBytes(to: sharedSecretPointer, count: sharedSecretBytes.count)
            return 0

        default:
            return -1  // Unsupported curve
        }
    } catch {
        return -2  // Error during key agreement
    }
}

// ECDSA for P-256, P-384, P-521 using CryptoKit

@_cdecl("go_generateKeyECDSA")
public func generateKeyECDSA(
    curveID: Int32,
    xPointer: UnsafeMutablePointer<UInt8>,
    xLen: Int,
    yPointer: UnsafeMutablePointer<UInt8>,
    yLen: Int,
    dPointer: UnsafeMutablePointer<UInt8>,
    dLen: Int
) -> Int {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0, xLen == keySize, yLen == keySize, dLen == keySize else {
        return -1  // Invalid key sizes
    }

    switch curveID {
    case 1:  // P-256
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let dData = privateKey.rawRepresentation
        let publicKeyData = publicKey.rawRepresentation

        dData.copyBytes(to: dPointer, count: keySize)
        publicKeyData.prefix(keySize).copyBytes(to: xPointer, count: keySize)
        publicKeyData.suffix(keySize).copyBytes(to: yPointer, count: keySize)
        return 0

    case 2:  // P-384
        let privateKey = P384.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let dData = privateKey.rawRepresentation
        let publicKeyData = publicKey.rawRepresentation

        dData.copyBytes(to: dPointer, count: keySize)
        publicKeyData.prefix(keySize).copyBytes(to: xPointer, count: keySize)
        publicKeyData.suffix(keySize).copyBytes(to: yPointer, count: keySize)
        return 0

    case 3:  // P-521
        let privateKey = P521.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let dData = privateKey.rawRepresentation
        let publicKeyData = publicKey.rawRepresentation

        dData.copyBytes(to: dPointer, count: keySize)
        publicKeyData.prefix(keySize).copyBytes(to: xPointer, count: keySize)
        publicKeyData.suffix(keySize).copyBytes(to: yPointer, count: keySize)
        return 0

    default:
        return -1  // Unsupported curve
    }
}

@_cdecl("go_ecdsaSign")
public func ecdsaSign(
    curveID: Int32,
    dPointer: UnsafePointer<UInt8>,
    dLen: Int,
    messagePointer: UnsafePointer<UInt8>,
    messageLen: Int,
    signaturePointer: UnsafeMutablePointer<UInt8>,
    signatureLen: UnsafeMutablePointer<Int>
) -> Int {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0, dLen == keySize else {
        return -1  // Invalid key size
    }

    do {
        let dData = Data(bytes: dPointer, count: dLen)
        let messageData = Data(bytes: messagePointer, count: messageLen)

        switch curveID {
        case 1:  // P-256
            let privateKey = try P256.Signing.PrivateKey(rawRepresentation: dData)
            let signature = try privateKey.signature(for: messageData)
            let derBytes = signature.derRepresentation
            guard derBytes.count <= 128 else { return -3 }  // Signature too large
            derBytes.copyBytes(to: signaturePointer, count: derBytes.count)
            signatureLen.pointee = derBytes.count
            return 0

        case 2:  // P-384
            let privateKey = try P384.Signing.PrivateKey(rawRepresentation: dData)
            let signature = try privateKey.signature(for: messageData)
            let derBytes = signature.derRepresentation
            guard derBytes.count <= 192 else { return -3 }  // Signature too large
            derBytes.copyBytes(to: signaturePointer, count: derBytes.count)
            signatureLen.pointee = derBytes.count
            return 0

        case 3:  // P-521
            let privateKey = try P521.Signing.PrivateKey(rawRepresentation: dData)
            let signature = try privateKey.signature(for: messageData)
            let derBytes = signature.derRepresentation
            guard derBytes.count <= 256 else { return -3 }  // Signature too large
            derBytes.copyBytes(to: signaturePointer, count: derBytes.count)
            signatureLen.pointee = derBytes.count
            return 0

        default:
            return -1  // Unsupported curve
        }
    } catch {
        return -2  // Error during signing
    }
}

@_cdecl("go_ecdsaVerify")
public func ecdsaVerify(
    curveID: Int32,
    xPointer: UnsafePointer<UInt8>,
    xLen: Int32,
    yPointer: UnsafePointer<UInt8>,
    yLen: Int32,
    messagePointer: UnsafePointer<UInt8>,
    messageLen: Int32,
    signaturePointer: UnsafePointer<UInt8>,
    signatureLen: Int32
) -> Int32 {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0, Int(xLen) == keySize, Int(yLen) == keySize else {
        return -1  // Invalid key sizes
    }

    do {
        let xData = Data(bytes: xPointer, count: Int(xLen))
        let yData = Data(bytes: yPointer, count: Int(yLen))
        let messageData = Data(bytes: messagePointer, count: Int(messageLen))
        let signatureDERData = Data(bytes: signaturePointer, count: Int(signatureLen))

        switch curveID {
        case 1:  // P-256
            let publicKeyData = xData + yData
            let publicKey = try P256.Signing.PublicKey(rawRepresentation: publicKeyData)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDERData)
            let isValid = publicKey.isValidSignature(signature, for: messageData)
            return isValid ? 1 : 0

        case 2:  // P-384
            let publicKeyData = xData + yData
            let publicKey = try P384.Signing.PublicKey(rawRepresentation: publicKeyData)
            let signature = try P384.Signing.ECDSASignature(derRepresentation: signatureDERData)
            let isValid = publicKey.isValidSignature(signature, for: messageData)
            return isValid ? 1 : 0

        case 3:  // P-521
            let publicKeyData = xData + yData
            let publicKey = try P521.Signing.PublicKey(rawRepresentation: publicKeyData)
            let signature = try P521.Signing.ECDSASignature(derRepresentation: signatureDERData)
            let isValid = publicKey.isValidSignature(signature, for: messageData)
            return isValid ? 1 : 0

        default:
            return -1  // Unsupported curve
        }
    } catch {
        return -2  // Error during verification
    }
}

@_cdecl("go_MD5")
public func MD5(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = Insecure.MD5.hash(data: inputData)

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("go_SHA1")
public func SHA1(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = Insecure.SHA1.hash(data: inputData)

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("go_SHA256")
public func SHA256(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = CryptoKit.SHA256.hash(data: inputData)

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("go_SHA384")
public func SHA384(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = CryptoKit.SHA384.hash(data: inputData)

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("go_SHA512")
public func SHA512(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = CryptoKit.SHA512.hash(data: inputData)

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

// SHA3 functions are only available when compiling with macOS 26.0+ SDK
#if compiler(>=6.2)
@available(macOS 26.0, *)
@_cdecl("go_SHA3_256")
public func SHA3_256(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = CryptoKit.SHA3_256.hash(data: inputData)
    let hashData = Data(hash)
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@available(macOS 26.0, *)
@_cdecl("go_SHA3_384")
public func SHA3_384(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = CryptoKit.SHA3_384.hash(data: inputData)
    let hashData = Data(hash)
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@available(macOS 26.0, *)
@_cdecl("go_SHA3_512")
public func SHA3_512(
    inputPointer: UnsafePointer<UInt8>,
    inputLength: Int,
    outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    let inputData = Data(bytes: inputPointer, count: inputLength)
    let hash = CryptoKit.SHA3_512.hash(data: inputData)
    let hashData = Data(hash)
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}
#endif

@_cdecl("go_hashNew")
public func hashNew(_ hashAlgorithm: Int32) -> UnsafeMutableRawPointer {
    switch hashAlgorithm {
    case 1:
        let hasher = UnsafeMutablePointer<Insecure.MD5>.allocate(capacity: 1)
        hasher.initialize(to: Insecure.MD5())
        return UnsafeMutableRawPointer(hasher)
    case 2:
        let hasher = UnsafeMutablePointer<Insecure.SHA1>.allocate(capacity: 1)
        hasher.initialize(to: Insecure.SHA1())
        return UnsafeMutableRawPointer(hasher)
    case 3:
        let hasher = UnsafeMutablePointer<CryptoKit.SHA256>.allocate(capacity: 1)
        hasher.initialize(to: CryptoKit.SHA256())
        return UnsafeMutableRawPointer(hasher)
    case 4:
        let hasher = UnsafeMutablePointer<CryptoKit.SHA384>.allocate(capacity: 1)
        hasher.initialize(to: CryptoKit.SHA384())
        return UnsafeMutableRawPointer(hasher)
    case 5:
        let hasher = UnsafeMutablePointer<CryptoKit.SHA512>.allocate(capacity: 1)
        hasher.initialize(to: CryptoKit.SHA512())
        return UnsafeMutableRawPointer(hasher)
    case 6:
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = UnsafeMutablePointer<CryptoKit.SHA3_256>.allocate(capacity: 1)
            hasher.initialize(to: CryptoKit.SHA3_256())
            return UnsafeMutableRawPointer(hasher)
        } else {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #else
        return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer (SHA3 not available)
        #endif
    case 7:
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = UnsafeMutablePointer<CryptoKit.SHA3_384>.allocate(capacity: 1)
            hasher.initialize(to: CryptoKit.SHA3_384())
            return UnsafeMutableRawPointer(hasher)
        } else {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #else
        return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer (SHA3 not available)
        #endif
    case 8:
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = UnsafeMutablePointer<CryptoKit.SHA3_512>.allocate(capacity: 1)
            hasher.initialize(to: CryptoKit.SHA3_512())
            return UnsafeMutableRawPointer(hasher)
        } else {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #else
        return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer (SHA3 not available)
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_hashWrite")
public func hashWrite(
    _ hashAlgorithm: Int32,
    _ ptr: UnsafeMutableRawPointer,
    _ data: UnsafePointer<UInt8>,
    _ length: Int
) {
    switch hashAlgorithm {
    case 1:
        let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
        let buffer = UnsafeRawBufferPointer(start: data, count: length)
        hasher.pointee.update(data: buffer)
    case 2:
        let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
        let buffer = UnsafeRawBufferPointer(start: data, count: length)
        hasher.pointee.update(data: buffer)
    case 3:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
        let buffer = UnsafeRawBufferPointer(start: data, count: length)
        hasher.pointee.update(data: buffer)
    case 4:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
        let buffer = UnsafeRawBufferPointer(start: data, count: length)
        hasher.pointee.update(data: buffer)
    case 5:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
        let buffer = UnsafeRawBufferPointer(start: data, count: length)
        hasher.pointee.update(data: buffer)
    case 6:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_256.self)
            let buffer = UnsafeRawBufferPointer(start: data, count: length)
            hasher.pointee.update(data: buffer)
        }
        #endif
    case 7:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_384.self)
            let buffer = UnsafeRawBufferPointer(start: data, count: length)
            hasher.pointee.update(data: buffer)
        }
        #endif
    case 8:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_512.self)
            let buffer = UnsafeRawBufferPointer(start: data, count: length)
            hasher.pointee.update(data: buffer)
        }
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}
@_cdecl("go_hashSum")
public func hashSum(
    _ hashAlgorithm: Int32,
    _ ptr: UnsafeMutableRawPointer,
    _ outputPointer: UnsafeMutablePointer<UInt8>
) {
    switch hashAlgorithm {
    case 1:
        let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
        let copiedHasher = hasher.pointee
        let hash = copiedHasher.finalize();

        let hashData = hash.withUnsafeBytes { Data($0) }
        hashData.copyBytes(to: outputPointer, count: hashData.count)
    case 2:
        let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
        let copiedHasher = hasher.pointee
        let hash = copiedHasher.finalize();

        let hashData = hash.withUnsafeBytes { Data($0) }
        hashData.copyBytes(to: outputPointer, count: hashData.count)
    case 3:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
        let copiedHasher = hasher.pointee
        let hash = copiedHasher.finalize();

        let hashData = hash.withUnsafeBytes { Data($0) }
        hashData.copyBytes(to: outputPointer, count: hashData.count)
    case 4:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
        let copiedHasher = hasher.pointee
        let hash = copiedHasher.finalize();

        let hashData = hash.withUnsafeBytes { Data($0) }
        hashData.copyBytes(to: outputPointer, count: hashData.count)
    case 5:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
        let copiedHasher = hasher.pointee
        let hash = copiedHasher.finalize();

        let hashData = hash.withUnsafeBytes { Data($0) }
        hashData.copyBytes(to: outputPointer, count: hashData.count)
    case 6:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_256.self)
            let copiedHasher = hasher.pointee
            let hash = copiedHasher.finalize();

            let hashData = Data(hash)
            hashData.copyBytes(to: outputPointer, count: hashData.count)
        }
        #endif
    case 7:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_384.self)
            let copiedHasher = hasher.pointee
            let hash = copiedHasher.finalize();

            let hashData = Data(hash)
            hashData.copyBytes(to: outputPointer, count: hashData.count)
        }
        #endif
    case 8:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_512.self)
            let copiedHasher = hasher.pointee
            let hash = copiedHasher.finalize();

            let hashData = Data(hash)
            hashData.copyBytes(to: outputPointer, count: hashData.count)
        }
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_hashReset")
public func hashReset(
    _ hashAlgorithm: Int32,
    _ ptr: UnsafeMutableRawPointer
) {
    switch hashAlgorithm {
    case 1:
        let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
        hasher.pointee = Insecure.MD5()
    case 2:
        let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
        hasher.pointee = Insecure.SHA1()
    case 3:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
        hasher.pointee = CryptoKit.SHA256()
    case 4:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
        hasher.pointee = CryptoKit.SHA384()
    case 5:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
        hasher.pointee = CryptoKit.SHA512()
    case 6:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_256.self)
            hasher.pointee = CryptoKit.SHA3_256()
        }
        #endif
    case 7:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_384.self)
            hasher.pointee = CryptoKit.SHA3_384()
        }
        #endif
    case 8:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, SHA-3 not supported
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_512.self)
            hasher.pointee = CryptoKit.SHA3_512()
        }
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_hashSize")
public func hashSize(_ hashAlgorithm: Int32) -> Int {
    switch hashAlgorithm {
    case 1:
        return Insecure.MD5.byteCount
    case 2:
        return Insecure.SHA1.byteCount
    case 3:
        return CryptoKit.SHA256.byteCount
    case 4:
        return CryptoKit.SHA384.byteCount
    case 5:
        return CryptoKit.SHA512.byteCount
    case 6:
        #if compiler(>=6.2)
        guard #available(macOS 26.0, *) else {
            return -1
        }
        return CryptoKit.SHA3_256.byteCount
        #else
        return -1
        #endif
    case 7:
        #if compiler(>=6.2)
        guard #available(macOS 26.0, *) else {
            return -1
        }
        return CryptoKit.SHA3_384.byteCount
        #else
        return -1
        #endif
    case 8:
        #if compiler(>=6.2)
        guard #available(macOS 26.0, *) else {
            return -1
        }
        return CryptoKit.SHA3_512.byteCount
        #else
        return -1
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_hashBlockSize")
public func hashBlockSize(_ hashAlgorithm: Int32) -> Int {
    switch hashAlgorithm {
    case 1:
        return Insecure.MD5.blockByteCount
    case 2:
        return Insecure.SHA1.blockByteCount
    case 3:
        return CryptoKit.SHA256.blockByteCount
    case 4:
        return CryptoKit.SHA384.blockByteCount
    case 5:
        return CryptoKit.SHA512.blockByteCount
    case 6:
        #if compiler(>=6.2)
        guard #available(macOS 26.0, *) else {
            return -1
        }
        return CryptoKit.SHA3_256.blockByteCount
        #else
        return -1
        #endif
    case 7:
        #if compiler(>=6.2)
        guard #available(macOS 26.0, *) else {
            return -1
        }
        return CryptoKit.SHA3_384.blockByteCount
        #else
        return -1
        #endif
    case 8:
        #if compiler(>=6.2)
        guard #available(macOS 26.0, *) else {
            return -1
        }
        return CryptoKit.SHA3_512.blockByteCount
        #else
        return -1
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_hashCopy")
public func hashCopy(_ hashAlgorithm: Int32, _ ptr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    switch hashAlgorithm {
    case 1:
        let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
        let copyOf = hasher.pointee
        let newHasher = UnsafeMutablePointer<Insecure.MD5>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 2:
        let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
        let copyOf = hasher.pointee
        let newHasher = UnsafeMutablePointer<Insecure.SHA1>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 3:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
        let copyOf = hasher.pointee
        let newHasher = UnsafeMutablePointer<CryptoKit.SHA256>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 4:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
        let copyOf = hasher.pointee
        let newHasher = UnsafeMutablePointer<CryptoKit.SHA384>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 5:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
        let copyOf = hasher.pointee
        let newHasher = UnsafeMutablePointer<CryptoKit.SHA512>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 6:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_256.self)
            let copyOf = hasher.pointee
            let newHasher = UnsafeMutablePointer<CryptoKit.SHA3_256>.allocate(capacity: 1)
            newHasher.initialize(to: copyOf)

            return UnsafeMutableRawPointer(newHasher)
        } else {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #else
        return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer (SHA3 not available)
        #endif
    case 7:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_384.self)
            let copyOf = hasher.pointee
            let newHasher = UnsafeMutablePointer<CryptoKit.SHA3_384>.allocate(capacity: 1)
            newHasher.initialize(to: copyOf)

            return UnsafeMutableRawPointer(newHasher)
        } else {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #else
        return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer (SHA3 not available)
        #endif
    case 8:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_512.self)
            let copyOf = hasher.pointee
            let newHasher = UnsafeMutablePointer<CryptoKit.SHA3_512>.allocate(capacity: 1)
            newHasher.initialize(to: copyOf)

            return UnsafeMutableRawPointer(newHasher)
        } else {
            return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer
        }
        #else
        return UnsafeMutableRawPointer(bitPattern: 1)!  // Return error pointer (SHA3 not available)
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_hashFree")
public func hashFree(_ hashAlgorithm: Int32, _ ptr: UnsafeMutableRawPointer) {
    switch hashAlgorithm {
    case 1:
        let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
        hasher.deallocate()
    case 2:
        let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
        hasher.deallocate()
    case 3:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
        hasher.deallocate()
    case 4:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
        hasher.deallocate()
    case 5:
        let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
        hasher.deallocate()
    case 6:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, nothing to deallocate
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_256.self)
            hasher.deallocate()
        }
        #endif
    case 7:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, nothing to deallocate
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_384.self)
            hasher.deallocate()
        }
        #endif
    case 8:
        if ptr == UnsafeMutableRawPointer(bitPattern: 1) {
            return  // Error pointer, nothing to deallocate
        }
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA3_512.self)
            hasher.deallocate()
        }
        #endif
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_extractHKDF")
public func extractHKDF(
    hashFunction: Int32,
    secretPointer: UnsafePointer<UInt8>,
    secretLength: Int,
    saltPointer: UnsafePointer<UInt8>,
    saltLength: Int,
    prkPointer: UnsafeMutablePointer<UInt8>,
    prkLength: Int
) -> Int {
    // Convert input pointers to Data
    let secretData: SymmetricKey = SymmetricKey(data: Data(bytes: secretPointer, count: secretLength))
    let saltData = Data(bytes: saltPointer, count: saltLength)

    let prk: any MessageAuthenticationCode

    switch hashFunction {
    case 1:
        prk = HKDF<Insecure.SHA1>.extract(
            inputKeyMaterial: secretData,
            salt: saltData
        )
    case 2:
        prk = HKDF<SHA256>.extract(
            inputKeyMaterial: secretData,
            salt: saltData
        )
    case 3:
        prk = HKDF<SHA384>.extract(
            inputKeyMaterial: secretData,
            salt: saltData
        )
    case 4:
        prk = HKDF<SHA512>.extract(
            inputKeyMaterial: secretData,
            salt: saltData
        )
    default:
        return -1  // Unsupported hash function
    }

    // Convert prk to Data
    let prkData = prk.withUnsafeBytes { Data($0) }

    prkData.copyBytes(to: prkPointer, count: prkData.count)

    return 0
}

@_cdecl("go_expandHKDF")
public func expandHKDF(
    hashFunction: Int32,
    prkPointer: UnsafePointer<UInt8>,
    prkLength: Int,
    infoPointer: UnsafePointer<UInt8>,
    infoLength: Int,
    derivedKeyPointer: UnsafeMutablePointer<UInt8>,
    derivedKeyLength: Int
) -> Int {
    // Convert input pointers to Data
    let prkData: SymmetricKey = SymmetricKey(data: Data(bytes: prkPointer, count: prkLength))
    let infoData = Data(bytes: infoPointer, count: infoLength)

    let derivedKey: SymmetricKey

    switch hashFunction {
    case 1:
        derivedKey = HKDF<Insecure.SHA1>.expand(
            pseudoRandomKey: prkData,
            info: infoData,
            outputByteCount: derivedKeyLength
        )
    case 2:
        derivedKey = HKDF<SHA256>.expand(
            pseudoRandomKey: prkData,
            info: infoData,
            outputByteCount: derivedKeyLength
        )
    case 3:
        derivedKey = HKDF<SHA384>.expand(
            pseudoRandomKey: prkData,
            info: infoData,
            outputByteCount: derivedKeyLength
        )
    case 4:
        derivedKey = HKDF<SHA512>.expand(
            pseudoRandomKey: prkData,
            info: infoData,
            outputByteCount: derivedKeyLength
        )
    default:
        return -1  // Unsupported hash function
    }

    // Convert derivedKey to Data
    let derivedKeyData = derivedKey.withUnsafeBytes { Data($0) }

    derivedKeyData.copyBytes(to: derivedKeyPointer, count: derivedKeyData.count)

    return 0
}

@_cdecl("go_initHMAC")
public func initHMAC(
    _ hashFunction: Int32,
    _ keyPointer: UnsafePointer<UInt8>,
    _ keyLength: Int
) -> UnsafeMutableRawPointer {
    let key: SymmetricKey = SymmetricKey(data: Data(bytes: keyPointer, count: keyLength))
    switch hashFunction {
    case 1:
        let hmac = UnsafeMutablePointer<HMAC<Insecure.MD5>>.allocate(capacity: 1)
        hmac.initialize(to: CryptoKit.HMAC<Insecure.MD5>(key: key))

        return UnsafeMutableRawPointer(hmac)
    case 2:
        let hmac = UnsafeMutablePointer<HMAC<Insecure.SHA1>>.allocate(capacity: 1)
        hmac.initialize(to: CryptoKit.HMAC<Insecure.SHA1>(key: key))

        return UnsafeMutableRawPointer(hmac)
    case 3:
        let hmac = UnsafeMutablePointer<HMAC<SHA256>>.allocate(capacity: 1)
        hmac.initialize(to: CryptoKit.HMAC<SHA256>(key: key))

        return UnsafeMutableRawPointer(hmac)
    case 4:
        let hmac = UnsafeMutablePointer<HMAC<SHA384>>.allocate(capacity: 1)
        hmac.initialize(to: CryptoKit.HMAC<SHA384>(key: key))

        return UnsafeMutableRawPointer(hmac)
    case 5:
        let hmac = UnsafeMutablePointer<HMAC<SHA512>>.allocate(capacity: 1)
        hmac.initialize(to: CryptoKit.HMAC<SHA512>(key: key))

        return UnsafeMutableRawPointer(hmac)
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_freeHMAC")
public func freeHMAC(_ hashFunction: Int32, _ ptr: UnsafeMutableRawPointer) {
    switch hashFunction {
    case 1:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.MD5>.self)
        hmac.deallocate()
    case 2:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.SHA1>.self)
        hmac.deallocate()
    case 3:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA256>.self)
        hmac.deallocate()
    case 4:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA384>.self)
        hmac.deallocate()
    case 5:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA512>.self)
        hmac.deallocate()
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_updateHMAC")
public func updateHMAC(
    _ hashFunction: Int32,
    _ ptr: UnsafeMutableRawPointer,
    _ data: UnsafePointer<UInt8>,
    _ length: Int
) -> Void {
    let data = Data(bytes: data, count: length)

    switch hashFunction {
    case 1:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.MD5>.self)
        hmac.pointee.update(data: data)
    case 2:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.SHA1>.self)
        hmac.pointee.update(data: data)
    case 3:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA256>.self)
        hmac.pointee.update(data: data)
    case 4:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA384>.self)
        hmac.pointee.update(data: data)
    case 5:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA512>.self)
        hmac.pointee.update(data: data)
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_copyHMAC")
public func copyHMAC(_ hashAlgorithm: Int32, _ ptr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    switch hashAlgorithm {
    case 1:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.MD5>.self)
        let copyOf = hmac.pointee
        let newHasher = UnsafeMutablePointer<HMAC<Insecure.MD5>>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 2:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.SHA1>.self)
        let copyOf = hmac.pointee
        let newHasher = UnsafeMutablePointer<HMAC<Insecure.SHA1>>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 3:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA256>.self)
        let copyOf = hmac.pointee
        let newHasher = UnsafeMutablePointer<HMAC<SHA256>>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 4:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA384>.self)
        let copyOf = hmac.pointee
        let newHasher = UnsafeMutablePointer<HMAC<SHA384>>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    case 5:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA512>.self)
        let copyOf = hmac.pointee
        let newHasher = UnsafeMutablePointer<HMAC<SHA512>>.allocate(capacity: 1)
        newHasher.initialize(to: copyOf)

        return UnsafeMutableRawPointer(newHasher)
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_finalizeHMAC")
public func finalizeHMAC(
    _ hashFunction: Int32,
    _ ptr: UnsafeMutableRawPointer,
    _ outputPointer: UnsafeMutablePointer<UInt8>
) -> Void {
    switch hashFunction {
    case 1:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.MD5>.self)
        let authenticationCode = hmac.pointee.finalize()
        Data(authenticationCode).copyBytes(to: outputPointer, count: Insecure.MD5.byteCount)
    case 2:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.SHA1>.self)
        let authenticationCode = hmac.pointee.finalize()
        Data(authenticationCode).copyBytes(to: outputPointer, count: Insecure.SHA1.byteCount)
    case 3:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA256>.self)
        let authenticationCode = hmac.pointee.finalize()
        Data(authenticationCode).copyBytes(to: outputPointer, count: CryptoKit.SHA256.byteCount)
    case 4:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA384>.self)
        let authenticationCode = hmac.pointee.finalize()
        Data(authenticationCode).copyBytes(to: outputPointer, count: CryptoKit.SHA384.byteCount)
    case 5:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA512>.self)
        let authenticationCode = hmac.pointee.finalize()
        Data(authenticationCode).copyBytes(to: outputPointer, count: CryptoKit.SHA512.byteCount)
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_hmacSize")
public func hmacSize(_ hashFunction: Int32) -> Int {
    switch hashFunction {
    case 1:
        return Insecure.MD5.byteCount
    case 2:
        return Insecure.SHA1.byteCount
    case 3:
        return CryptoKit.SHA256.byteCount
    case 4:
        return CryptoKit.SHA384.byteCount
    case 5:
        return CryptoKit.SHA512.byteCount
    default:
        fatalError("Unsupported hash function")
    }
}

@_cdecl("go_resetHMAC")
public func resetHMAC(
    _ hashFunction: Int32,
    _ ptr: UnsafeMutableRawPointer,
    _ keyPointer: UnsafePointer<UInt8>,
    _ keyLength: Int
) {
    let key: SymmetricKey = SymmetricKey(data: Data(bytes: keyPointer, count: keyLength))
    switch hashFunction {
    case 1:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.MD5>.self)
        hmac.pointee = CryptoKit.HMAC<Insecure.MD5>(key: key)
    case 2:
        let hmac = ptr.assumingMemoryBound(to: HMAC<Insecure.SHA1>.self)
        hmac.pointee = CryptoKit.HMAC<Insecure.SHA1>(key: key)
    case 3:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA256>.self)
        hmac.pointee = CryptoKit.HMAC<SHA256>(key: key)
    case 4:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA384>.self)
        hmac.pointee = CryptoKit.HMAC<SHA384>(key: key)
    case 5:
        let hmac = ptr.assumingMemoryBound(to: HMAC<SHA512>.self)
        hmac.pointee = CryptoKit.HMAC<SHA512>(key: key)
    default:
        fatalError("Unsupported hash function")
    }
}

// ML-KEM (Post-quantum key encapsulation mechanism)
// Runtime feature detection for ML-KEM (available on macOS 26+ only)
@_cdecl("go_supportsMLKEM")
public func supportsMLKEM() -> Int {
    if #available(macOS 26.0, *) {
        // ML-KEM symbols are lazily bound, so if this returns true,
        // the runtime can safely call ML-KEM functions.
        return 1
    }
    return 0
}

// ML-KEM-768 functions
#if compiler(>=6.2)
@available(macOS 26.0, *)
@_cdecl("go_generateKeyMLKEM768")
public func generateKeyMLKEM768(seedPointer: UnsafeMutablePointer<UInt8>, seedLen: Int) -> Int {
    do {
        let privateKey = try MLKEM768.PrivateKey()
        let seedData = privateKey.seedRepresentation
        guard seedLen == seedData.count else { return 1 }
        let buffer = UnsafeMutableRawBufferPointer(start: seedPointer, count: seedLen)
        seedData.copyBytes(to: buffer)
        return 0
    } catch {
        return 1
    }
}

@available(macOS 26.0, *)
@_cdecl("go_deriveEncapsulationKeyMLKEM768")
public func deriveEncapsulationKeyMLKEM768(
    seedPointer: UnsafePointer<UInt8>,
    seedLen: Int,
    encapKeyPointer: UnsafeMutablePointer<UInt8>,
    encapKeyLen: Int
) -> Int {
    do {
        let seedData = Data(bytes: seedPointer, count: seedLen)
        let privateKey = try MLKEM768.PrivateKey(seedRepresentation: seedData, publicKey: nil)
        guard seedLen == privateKey.seedRepresentation.count else { return 1 }
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        guard encapKeyLen == publicKeyData.count else { return 1 }
        let buffer = UnsafeMutableRawBufferPointer(start: encapKeyPointer, count: encapKeyLen)
        publicKeyData.copyBytes(to: buffer)
        return 0
    } catch {
        return 1
    }
}

@available(macOS 26.0, *)
@_cdecl("go_encapsulateMLKEM768")
public func encapsulateMLKEM768(
    encapKeyPointer: UnsafePointer<UInt8>,
    encapKeyLen: Int,
    sharedKeyPointer: UnsafeMutablePointer<UInt8>,
    sharedKeyLen: Int,
    ciphertextPointer: UnsafeMutablePointer<UInt8>,
    ciphertextLen: Int
) -> Int {
    do {
        let publicKeyData = Data(bytes: encapKeyPointer, count: encapKeyLen)
        let publicKey = try MLKEM768.PublicKey(rawRepresentation: publicKeyData)
        let encapResult = try publicKey.encapsulate()

        guard sharedKeyLen >= encapResult.sharedSecret.withUnsafeBytes({ $0.count }),
            ciphertextLen >= encapResult.encapsulated.count
        else { return 1 }

        let sharedKeyBuffer = UnsafeMutableRawBufferPointer(start: sharedKeyPointer, count: sharedKeyLen)
        let ciphertextBuffer = UnsafeMutableRawBufferPointer(start: ciphertextPointer, count: ciphertextLen)
        encapResult.sharedSecret.withUnsafeBytes { bytes in
            sharedKeyBuffer.copyBytes(from: bytes)
        }
        encapResult.encapsulated.copyBytes(to: ciphertextBuffer)
        return 0
    } catch {
        return 1
    }
}

@available(macOS 26.0, *)
@_cdecl("go_decapsulateMLKEM768")
public func decapsulateMLKEM768(
    seedPointer: UnsafePointer<UInt8>,
    seedLen: Int,
    ciphertextPointer: UnsafePointer<UInt8>,
    ciphertextLen: Int,
    sharedKeyPointer: UnsafeMutablePointer<UInt8>,
    sharedKeyLen: Int
) -> Int {
    do {
        let seedData = Data(bytes: seedPointer, count: seedLen)
        let privateKey = try MLKEM768.PrivateKey(seedRepresentation: seedData, publicKey: nil)
        guard seedLen == privateKey.seedRepresentation.count else { return 1 }
        let ciphertextData = Data(bytes: ciphertextPointer, count: ciphertextLen)
        let sharedKey = try privateKey.decapsulate(ciphertextData)
        guard sharedKeyLen >= sharedKey.withUnsafeBytes({ $0.count }) else { return 1 }
        sharedKey.withUnsafeBytes { sharedKeyBytes in
            let sharedKeyBuffer = UnsafeMutableRawBufferPointer(start: sharedKeyPointer, count: sharedKeyLen)
            sharedKeyBuffer.copyBytes(from: sharedKeyBytes)
        }
        return 0
    } catch {
        return 1
    }
}

// ML-KEM-1024 functions
@available(macOS 26.0, *)
@_cdecl("go_generateKeyMLKEM1024")
public func generateKeyMLKEM1024(seedPointer: UnsafeMutablePointer<UInt8>, seedLen: Int) -> Int {
    do {
        let privateKey = try MLKEM1024.PrivateKey()
        let seedData = privateKey.seedRepresentation
        guard seedLen == seedData.count else { return 1 }
        let buffer = UnsafeMutableRawBufferPointer(start: seedPointer, count: seedLen)
        seedData.copyBytes(to: buffer)
        return 0
    } catch {
        return 1
    }
}

@available(macOS 26.0, *)
@_cdecl("go_deriveEncapsulationKeyMLKEM1024")
public func deriveEncapsulationKeyMLKEM1024(
    seedPointer: UnsafePointer<UInt8>,
    seedLen: Int,
    encapKeyPointer: UnsafeMutablePointer<UInt8>,
    encapKeyLen: Int
) -> Int {
    do {
        let seedData = Data(bytes: seedPointer, count: seedLen)
        let privateKey = try MLKEM1024.PrivateKey(seedRepresentation: seedData, publicKey: nil)
        guard seedLen == privateKey.seedRepresentation.count else { return 1 }
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        guard encapKeyLen == publicKeyData.count else { return 1 }
        let buffer = UnsafeMutableRawBufferPointer(start: encapKeyPointer, count: encapKeyLen)
        publicKeyData.copyBytes(to: buffer)
        return 0
    } catch {
        return 1
    }
}

@available(macOS 26.0, *)
@_cdecl("go_encapsulateMLKEM1024")
public func encapsulateMLKEM1024(
    encapKeyPointer: UnsafePointer<UInt8>,
    encapKeyLen: Int,
    sharedKeyPointer: UnsafeMutablePointer<UInt8>,
    sharedKeyLen: Int,
    ciphertextPointer: UnsafeMutablePointer<UInt8>,
    ciphertextLen: Int
) -> Int {
    do {
        let publicKeyData = Data(bytes: encapKeyPointer, count: encapKeyLen)
        let publicKey = try MLKEM1024.PublicKey(rawRepresentation: publicKeyData)
        let encapResult = try publicKey.encapsulate()

        guard sharedKeyLen >= encapResult.sharedSecret.withUnsafeBytes({ $0.count }),
            ciphertextLen >= encapResult.encapsulated.count
        else { return 1 }

        let sharedKeyBuffer = UnsafeMutableRawBufferPointer(start: sharedKeyPointer, count: sharedKeyLen)
        let ciphertextBuffer = UnsafeMutableRawBufferPointer(start: ciphertextPointer, count: ciphertextLen)
        encapResult.sharedSecret.withUnsafeBytes { bytes in
            sharedKeyBuffer.copyBytes(from: bytes)
        }
        encapResult.encapsulated.copyBytes(to: ciphertextBuffer)
        return 0
    } catch {
        return 1
    }
}

@available(macOS 26.0, *)
@_cdecl("go_decapsulateMLKEM1024")
public func decapsulateMLKEM1024(
    seedPointer: UnsafePointer<UInt8>,
    seedLen: Int,
    ciphertextPointer: UnsafePointer<UInt8>,
    ciphertextLen: Int,
    sharedKeyPointer: UnsafeMutablePointer<UInt8>,
    sharedKeyLen: Int
) -> Int {
    do {
        let seedData = Data(bytes: seedPointer, count: seedLen)
        let privateKey = try MLKEM1024.PrivateKey(seedRepresentation: seedData, publicKey: nil)
        guard seedLen == privateKey.seedRepresentation.count else { return 1 }
        let ciphertextData = Data(bytes: ciphertextPointer, count: ciphertextLen)
        let sharedKey = try privateKey.decapsulate(ciphertextData)
        guard sharedKeyLen >= sharedKey.withUnsafeBytes({ $0.count }) else { return 1 }
        sharedKey.withUnsafeBytes { sharedKeyBytes in
            let sharedKeyBuffer = UnsafeMutableRawBufferPointer(start: sharedKeyPointer, count: sharedKeyLen)
            sharedKeyBuffer.copyBytes(from: sharedKeyBytes)
        }
        return 0
    } catch {
        return 1
    }
}
#endif

// ECDH Key Validation
@_cdecl("go_validatePrivateKeyECDH")
public func validatePrivateKeyECDH(
    curveID: Int32,
    privateKeyPointer: UnsafePointer<UInt8>,
    privateKeyLen: Int
) -> Int {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0, privateKeyLen == keySize else {
        return -1  // Invalid key size
    }

    do {
        let privateKeyData = Data(bytes: privateKeyPointer, count: privateKeyLen)

        switch curveID {
        case 0:  // X25519
            _ = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            return 0  // Valid
        case 1:  // P-256
            _ = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            return 0  // Valid
        case 2:  // P-384
            _ = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            return 0  // Valid
        case 3:  // P-521
            _ = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            return 0  // Valid
        default:
            return -1  // Unsupported curve
        }
    } catch {
        return -2  // Invalid key
    }
}

@_cdecl("go_validatePublicKeyECDH")
public func validatePublicKeyECDH(
    curveID: Int32,
    publicKeyPointer: UnsafePointer<UInt8>,
    publicKeyLen: Int
) -> Int {
    let keySize = getECDHKeySizeForCurve(curveID)
    guard keySize > 0 else { return -1 }

    if curveID == 0 {
        // X25519
        guard publicKeyLen == keySize else { return -1 }
        do {
            let publicKeyData = Data(bytes: publicKeyPointer, count: publicKeyLen)
            _ = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
            return 0
        } catch {
            return -2
        }
    }

    guard publicKeyLen == 1 + keySize * 2 else {
        return -1  // Invalid key size
    }

    do {
        // Use x963Representation which includes the 0x04 prefix and performs validation
        let publicKeyData = Data(bytes: publicKeyPointer, count: publicKeyLen)

        switch curveID {
        case 1:  // P-256
            _ = try P256.KeyAgreement.PublicKey(x963Representation: publicKeyData)
            return 0  // Valid
        case 2:  // P-384
            _ = try P384.KeyAgreement.PublicKey(x963Representation: publicKeyData)
            return 0  // Valid
        case 3:  // P-521
            _ = try P521.KeyAgreement.PublicKey(x963Representation: publicKeyData)
            return 0  // Valid
        default:
            return -1  // Unsupported curve
        }
    } catch {
        return -2  // Invalid key
    }
}
