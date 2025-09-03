// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

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
        print("Encryption failed with error: \(error)")
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
        print("Decryption failed with error: \(error)")
        return 1
    }
}
