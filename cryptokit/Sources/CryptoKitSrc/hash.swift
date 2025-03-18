// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

@_cdecl("MD5")
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

@_cdecl("SHA1")
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

@_cdecl("SHA256")
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

@_cdecl("SHA384")
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

@_cdecl("SHA512")
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
