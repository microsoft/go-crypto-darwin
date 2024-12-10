// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

@_cdecl("generateKeyEd25519")
public func generateKeyEd25519() -> UnsafeMutableRawPointer? {
    // Generate a private key using CryptoKit
    let privateKey = Curve25519.Signing.PrivateKey()

    // Extract the raw representation of the private key
    let privateKeyData = privateKey.rawRepresentation

    // Allocate memory for the private key data and copy it
    let keyPointer = UnsafeMutableRawPointer.allocate(byteCount: privateKeyData.count, alignment: 1)
    privateKeyData.copyBytes(to: keyPointer.assumingMemoryBound(to: UInt8.self), count: privateKeyData.count)

    // Return the pointer to the raw key data
    return keyPointer
}

@_cdecl("newPrivateKeyEd25519FromSeed")
public func newPrivateKeyEd25519FromSeed(
    seedPointer: UnsafePointer<UInt8>?,
    seedLength: Int
) -> UnsafeMutableRawPointer? {
    guard let seedPointer = seedPointer, seedLength == 32 else {
        // Invalid seed length, return nil
        return nil
    }

    // Copy the seed into a Data object
    let seedData = Data(bytes: seedPointer, count: seedLength)

    // Generate the private key from the seed
    let privateKey: Curve25519.Signing.PrivateKey
    do {
        privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedData)
    } catch {
        // Key generation failed, return nil
        return nil
    }

    // Extract the raw representation of the private key
    let privateKeyData = privateKey.rawRepresentation

    // Allocate memory for the private key data and copy it
    let keyPointer = UnsafeMutableRawPointer.allocate(byteCount: privateKeyData.count, alignment: 1)
    privateKeyData.copyBytes(to: keyPointer.assumingMemoryBound(to: UInt8.self), count: privateKeyData.count)

    return keyPointer
}

@_cdecl("newPublicKeyEd25519")
public func newPublicKeyEd25519(pubPointer: UnsafePointer<UInt8>?, pubLength: Int) -> UnsafeMutableRawPointer? {
    guard let pubPointer = pubPointer, pubLength == 32 else {
        // Invalid public key length
        return nil
    }

    // Copy the public key bytes into a Data object
    let pubData = Data(bytes: pubPointer, count: pubLength)

    do {
        // Create the public key from the raw representation
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubData)

        // Store the public key in memory and return the pointer
        let keyPointer = UnsafeMutableRawPointer.allocate(byteCount: 32, alignment: 1)
        publicKey.rawRepresentation.copyBytes(to: keyPointer.assumingMemoryBound(to: UInt8.self), count: 32)
        return keyPointer
    } catch {
        // Failed to create the public key
        return nil
    }
}

@_cdecl("getPrivateKeyEd25519Bytes")
public func getPrivateKeyEd25519Bytes(
    keyPointer: UnsafeRawPointer?,
    buffer: UnsafeMutablePointer<UInt8>?,
    bufferLength: Int
) -> Int {
    guard let keyPointer = keyPointer, let buffer = buffer else {
        return -1  // Error: invalid inputs
    }

    // Convert the raw pointer back to the seed (32 bytes)
    let seed = Data(bytes: keyPointer, count: 32)

    // Reconstruct the private key from the seed
    let privateKey: Curve25519.Signing.PrivateKey
    do {
        privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    } catch {
        return -1  // Error: key reconstruction failed
    }

    // Extract the public key
    let publicKey = privateKey.publicKey.rawRepresentation

    // Concatenate the seed and public key
    var privateKeyFull = seed
    privateKeyFull.append(publicKey)

    // Ensure the buffer is large enough
    guard bufferLength >= privateKeyFull.count else {
        return -2  // Error: buffer too small
    }

    // Copy the concatenated key into the buffer
    privateKeyFull.copyBytes(to: buffer, count: privateKeyFull.count)

    return privateKeyFull.count  // Return the number of bytes written (64)
}

@_cdecl("extractPublicKeyEd25519")
public func extractPublicKeyEd25519(
    privateKeyPointer: UnsafeRawPointer?,
    buffer: UnsafeMutablePointer<UInt8>?,
    bufferLength: Int
) -> Int {
    guard let privateKeyPointer = privateKeyPointer, let buffer = buffer else {
        return -1  // Invalid input
    }

    // Convert the raw pointer back to the private key seed (32 bytes)
    let privateKeySeed = Data(bytes: privateKeyPointer, count: 32)

    // Reconstruct the private key from the seed
    let privateKey: Curve25519.Signing.PrivateKey
    do {
        privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeySeed)
    } catch {
        return -1  // Failed to reconstruct private key
    }

    // Extract the public key
    let publicKey = privateKey.publicKey.rawRepresentation

    // Ensure the buffer is large enough
    guard bufferLength >= publicKey.count else {
        return -2  // Buffer too small
    }

    // Copy the public key bytes into the buffer
    publicKey.copyBytes(to: buffer, count: publicKey.count)

    return publicKey.count  // Return the number of bytes written (32)
}

@_cdecl("signEd25519")
public func signEd25519(
    privateKeyPointer: UnsafeRawPointer?,
    messagePointer: UnsafePointer<UInt8>?,
    messageLength: Int,
    sigBuffer: UnsafeMutablePointer<UInt8>?,
    sigBufferLength: Int
) -> Int {
    guard let privateKeyPointer = privateKeyPointer,
        let messagePointer = messagePointer,
        let sigBuffer = sigBuffer
    else {
        return -1  // Invalid inputs
    }

    // Convert the raw private key back to the seed (32 bytes)
    let privateKeySeed = Data(bytes: privateKeyPointer, count: 32)

    // Reconstruct the private key
    let privateKey: Curve25519.Signing.PrivateKey
    do {
        privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeySeed)
    } catch {
        return -2  // Failed to reconstruct private key
    }

    // Convert the message to Data
    let messageData = Data(bytes: messagePointer, count: messageLength)

    // Sign the message
    let signature: Data
    do {
        signature = try privateKey.signature(for: messageData)
    } catch {
        return -3  // Failed to sign the message
    }

    // Ensure the buffer is large enough
    guard sigBufferLength >= signature.count else {
        return -4  // Buffer too small
    }

    // Copy the signature to the buffer
    signature.copyBytes(to: sigBuffer, count: signature.count)

    return signature.count  // Return the number of bytes written
}

@_cdecl("verifyEd25519")
public func verifyEd25519(
    publicKeyPointer: UnsafeRawPointer?,
    messagePointer: UnsafePointer<UInt8>?,
    messageLength: Int,
    sigPointer: UnsafePointer<UInt8>?,
    sigLength: Int
) -> Int {
    guard let publicKeyPointer = publicKeyPointer,
        let messagePointer = messagePointer,
        let sigPointer = sigPointer
    else {
        return -1  // Error: invalid inputs
    }

    // Convert the raw public key back to a Data object
    let publicKeyData = Data(bytes: publicKeyPointer, count: 32)

    // Reconstruct the public key
    guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else {
        return -2  // Error: failed to reconstruct public key
    }

    // Convert the message and signature to Data
    let rawMessage = Data(bytes: messagePointer, count: messageLength)
    let signatureData = Data(bytes: sigPointer, count: sigLength)

    // Verify the signature
    let isValid = publicKey.isValidSignature(signatureData, for: rawMessage)
    return isValid ? 1 : 0  // Return 1 for valid, 0 for invalid
}

@_cdecl("freeKeyEd25519")
public func freeKeyEd25519(_ keyPointer: UnsafeMutableRawPointer?) {
    // Free the allocated memory
    keyPointer?.deallocate()
}
