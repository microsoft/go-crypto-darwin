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

@_cdecl("NewMD5")
public func NewMD5() -> UnsafeMutableRawPointer {
    let hasher = UnsafeMutablePointer<Insecure.MD5>.allocate(capacity: 1)
    hasher.initialize(to: Insecure.MD5())
    return UnsafeMutableRawPointer(hasher)
}

@_cdecl("MD5Write")
public func MD5Write(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ length: Int) -> Int {
    let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
    let buffer = UnsafeRawBufferPointer(start: data, count: length)

    hasher.pointee.update(data: buffer)
    
    return length // Always return full length as Swift doesn't have partial writes
}

@_cdecl("MD5Sum")
public func MD5Sum(_ ptr: UnsafeMutableRawPointer, _ outputPointer: UnsafeMutablePointer<UInt8>) {
    let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
    let copiedHasher = hasher.pointee
    let hash = copiedHasher.finalize();

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("MD5Reset")
public func MD5Reset(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
    hasher.pointee = Insecure.MD5()
}

@_cdecl("MD5Size")
public func MD5BSize() -> Int {
    return Insecure.MD5.byteCount
}

@_cdecl("MD5BlockSize")
public func MD5BlockSize() -> Int {
    return Insecure.MD5.blockByteCount
}

@_cdecl("MD5Copy")
public func MD5Copy(_ ptr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
    let copyOf = hasher.pointee
    let newHasher = UnsafeMutablePointer<Insecure.MD5>.allocate(capacity: 1)
    newHasher.initialize(to: copyOf)

    return UnsafeMutableRawPointer(newHasher)
}

@_cdecl("MD5Free")
public func MD5Free(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: Insecure.MD5.self)
    hasher.deallocate()
}

@_cdecl("NewSHA1")
public func NewSHA1() -> UnsafeMutableRawPointer {
    let hasher = UnsafeMutablePointer<Insecure.SHA1>.allocate(capacity: 1)
    hasher.initialize(to: Insecure.SHA1())
    return UnsafeMutableRawPointer(hasher)
}

@_cdecl("SHA1Write")
public func SHA1Write(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ length: Int) -> Int {
    let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
    let buffer = UnsafeRawBufferPointer(start: data, count: length)

    hasher.pointee.update(data: buffer)
    
    return length // Always return full length as Swift doesn't have partial writes
}

@_cdecl("SHA1Sum")
public func SHA1Sum(_ ptr: UnsafeMutableRawPointer, _ outputPointer: UnsafeMutablePointer<UInt8>) {
    let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
    let copiedHasher = hasher.pointee
    let hash = copiedHasher.finalize();

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("SHA1Reset")
public func SHA1Reset(_ sha1Ptr: UnsafeMutableRawPointer) {
    let hasher = sha1Ptr.assumingMemoryBound(to: Insecure.SHA1.self)
    hasher.pointee = Insecure.SHA1()
}

@_cdecl("SHA1Size")
public func SHA1Size() -> Int {
    return Insecure.SHA1.byteCount
}

@_cdecl("SHA1BlockSize")
public func SHA1BlockSize() -> Int {
    return Insecure.SHA1.blockByteCount
}

@_cdecl("SHA1Copy")
public func SHA1Copy(_ ptr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
    let copyOf = hasher.pointee
    let newHasher = UnsafeMutablePointer<Insecure.SHA1>.allocate(capacity: 1)
    newHasher.initialize(to: copyOf)

    return UnsafeMutableRawPointer(newHasher)
}

@_cdecl("SHA1Free")
public func SHA1Free(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: Insecure.SHA1.self)
    hasher.deallocate()
}


@_cdecl("NewSHA256")
public func NewSHA256() -> UnsafeMutableRawPointer {
    let hasher = UnsafeMutablePointer<CryptoKit.SHA256>.allocate(capacity: 1)
    hasher.initialize(to: CryptoKit.SHA256())
    return UnsafeMutableRawPointer(hasher)
}

@_cdecl("SHA256Write")
public func SHA256Write(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ length: Int) -> Int {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
    let buffer = UnsafeRawBufferPointer(start: data, count: length)

    hasher.pointee.update(data: buffer)
    return length // Always return full length as Swift doesn't have partial writes
}

@_cdecl("SHA256Sum")
public func SHA256Sum(_ ptr: UnsafeMutableRawPointer, _ outputPointer: UnsafeMutablePointer<UInt8>) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
    let copiedHasher = hasher.pointee
    let hash = copiedHasher.finalize();

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("SHA256Reset")
public func SHA256Reset(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
    hasher.pointee = CryptoKit.SHA256()
}

@_cdecl("SHA256Size")
public func SHA256Size() -> Int {
    return CryptoKit.SHA256.byteCount
}

@_cdecl("SHA256BlockSize")
public func SHA256BlockSize() -> Int {
    return CryptoKit.SHA256.blockByteCount
}

@_cdecl("SHA256Copy")
public func SHA256Copy(_ ptr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
    let copyOf = hasher.pointee
    let newHasher = UnsafeMutablePointer<CryptoKit.SHA256>.allocate(capacity: 1)
    newHasher.initialize(to: copyOf)

    return UnsafeMutableRawPointer(newHasher)
}

@_cdecl("SHA256Free")
public func SHA256Free(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA256.self)
    hasher.deallocate()
}


@_cdecl("NewSHA384")
public func NewSHA384() -> UnsafeMutableRawPointer {
    let hasher = UnsafeMutablePointer<CryptoKit.SHA384>.allocate(capacity: 1)
    hasher.initialize(to: CryptoKit.SHA384())
    return UnsafeMutableRawPointer(hasher)
}

@_cdecl("SHA384Write")
public func SHA384Write(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ length: Int) -> Int {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
    let buffer = UnsafeRawBufferPointer(start: data, count: length)

    hasher.pointee.update(data: buffer)
    
    return length // Always return full length as Swift doesn't have partial writes
}

@_cdecl("SHA384Sum")
public func SHA384Sum(_ ptr: UnsafeMutableRawPointer, _ outputPointer: UnsafeMutablePointer<UInt8>) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
    let copiedHasher = hasher.pointee
    let hash = copiedHasher.finalize();

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("SHA384Reset")
public func SHA384Reset(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
    hasher.pointee = CryptoKit.SHA384()
}

@_cdecl("SHA384Copy")
public func SHA384Copy(_ ptr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
    let copyOf = hasher.pointee
    let newHasher = UnsafeMutablePointer<CryptoKit.SHA384>.allocate(capacity: 1)
    newHasher.initialize(to: copyOf)

    return UnsafeMutableRawPointer(newHasher)
}

@_cdecl("SHA384Size")
public func SHA384Size() -> Int {
    return CryptoKit.SHA384.byteCount
}

@_cdecl("SHA384BlockSize")
public func SHA384BlockSize() -> Int {
    return CryptoKit.SHA384.blockByteCount
}

@_cdecl("SHA384Free")
public func SHA384Free(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA384.self)
    hasher.deallocate()
}

@_cdecl("NewSHA512")
public func NewSHA512() -> UnsafeMutableRawPointer {
    let hasher = UnsafeMutablePointer<CryptoKit.SHA512>.allocate(capacity: 1)
    hasher.initialize(to: CryptoKit.SHA512())
    return UnsafeMutableRawPointer(hasher)
}

@_cdecl("SHA512Write")
public func SHA512Write(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ length: Int) -> Int {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
    let buffer = UnsafeRawBufferPointer(start: data, count: length)

    hasher.pointee.update(data: buffer)
    
    return length // Always return full length as Swift doesn't have partial writes
}

@_cdecl("SHA512Sum")
public func SHA512Sum(_ ptr: UnsafeMutableRawPointer, _ outputPointer: UnsafeMutablePointer<UInt8>) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
    let copiedHasher = hasher.pointee
    let hash = copiedHasher.finalize();

    let hashData = hash.withUnsafeBytes { Data($0) }
    hashData.copyBytes(to: outputPointer, count: hashData.count)
}

@_cdecl("SHA512Reset")
public func SHA512Reset(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
    hasher.pointee = CryptoKit.SHA512()
}

@_cdecl("SHA512Size")
public func SHA512Size() -> Int {
    return CryptoKit.SHA512.byteCount
}

@_cdecl("SHA512BlockSize")
public func SHA512BlockSize() -> Int {
    return CryptoKit.SHA512.blockByteCount
}

@_cdecl("SHA512Copy")
public func SHA512Copy(_ ptr: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
    let copyOf = hasher.pointee
    let newHasher = UnsafeMutablePointer<CryptoKit.SHA512>.allocate(capacity: 1)
    newHasher.initialize(to: copyOf)

    return UnsafeMutableRawPointer(newHasher)
}

@_cdecl("SHA512Free")
public func SHA512Free(_ ptr: UnsafeMutableRawPointer) {
    let hasher = ptr.assumingMemoryBound(to: CryptoKit.SHA512.self)
    hasher.deallocate()
}
