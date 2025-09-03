// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

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
    default:
        fatalError("Unsupported hash function")
    }
}
