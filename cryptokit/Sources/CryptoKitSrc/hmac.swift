// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation

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
