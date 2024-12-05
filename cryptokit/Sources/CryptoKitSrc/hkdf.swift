// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

@_cdecl("extractHKDF")
public func extractHKDF(
    hashFunction: Int32,
    secretPointer: UnsafePointer<UInt8>, secretLength: Int,
    saltPointer: UnsafePointer<UInt8>, saltLength: Int,
    prkPointer: UnsafeMutablePointer<UInt8>, prkLength: Int
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
        return -1 // Unsupported hash function
    }

    // Convert prk to Data
    let prkData = prk.withUnsafeBytes { Data($0) }

    prkData.copyBytes(to: prkPointer, count: prkData.count)

    return 0
}

@_cdecl("expandHKDF")
public func expandHKDF(
    hashFunction: Int32,
    prkPointer: UnsafePointer<UInt8>, prkLength: Int,
    infoPointer: UnsafePointer<UInt8>, infoLength: Int,
    derivedKeyPointer: UnsafeMutablePointer<UInt8>, derivedKeyLength: Int
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
        return -1 // Unsupported hash function
    }

    // Convert derivedKey to Data
    let derivedKeyData = derivedKey.withUnsafeBytes { Data($0) }

    derivedKeyData.copyBytes(to: derivedKeyPointer, count: derivedKeyData.count)

    return 0
}