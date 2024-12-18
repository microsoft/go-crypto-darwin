// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

var publicKeySizeEd25519 = 32
var signatureSizeEd25519 = 64
var seedSizeEd25519 = 32

@_cdecl("generateKeyEd25519")
public func generateKeyEd25519(keyPointer: UnsafeMutablePointer<UInt8>) -> Void {
    // Generate a private key using CryptoKit
    let privateKey = Curve25519.Signing.PrivateKey()

    // Extract the raw representation of the private key
    let privateKeyData = privateKey.rawRepresentation

    // Allocate memory for the private key data and copy it
    privateKeyData.copyBytes(to: keyPointer, count: privateKeyData.count)
    privateKey.publicKey.rawRepresentation.copyBytes(to: keyPointer + publicKeySizeEd25519, count: publicKeySizeEd25519)
}

@_cdecl("newPrivateKeyEd25519FromSeed")
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

@_cdecl("newPublicKeyEd25519")
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

@_cdecl("signEd25519")
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

@_cdecl("verifyEd25519")
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
