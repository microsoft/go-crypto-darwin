// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

@_cdecl("initMAC")
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

@_cdecl("freeHMAC")
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

@_cdecl("updateHMAC")
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

@_cdecl("finalizeHMAC")
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
