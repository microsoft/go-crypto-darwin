// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest
import Foundation
@testable import CryptoKitSrc

final class CryptoKitTests: XCTestCase {
    
    // Test string and its known hash values
    let testString = "The quick brown fox jumps over the lazy dog"
    let emptyString = ""
    
    // Test MD5 hash function
    func testMD5() {
        let input = Array(testString.utf8)
        var output = [UInt8](repeating: 0, count: 16) // MD5 is 16 bytes
        
        MD5(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )
        
        // Known MD5 hash for the test string (as hex)
        let expectedHex = "9e107d9d372bb6826bd81d3542a419d6"
        XCTAssertEqual(Data(output).hexString, expectedHex)
        
        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        MD5(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &output
        )
        
        // Known MD5 hash for empty string
        let emptyExpectedHex = "d41d8cd98f00b204e9800998ecf8427e"
        XCTAssertEqual(Data(output).hexString, emptyExpectedHex)
    }
    
    // Test SHA1 hash function
    func testSHA1() {
        let input = Array(testString.utf8)
        var output = [UInt8](repeating: 0, count: 20) // SHA1 is 20 bytes
        
        SHA1(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )
        
        // Known SHA1 hash for the test string
        let expectedHex = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        XCTAssertEqual(Data(output).hexString, expectedHex)
        
        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        SHA1(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &output
        )
        
        // Known SHA1 hash for empty string
        let emptyExpectedHex = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        XCTAssertEqual(Data(output).hexString, emptyExpectedHex)
    }
    
    // Test SHA256 hash function
    func testSHA256() {
        let input = Array(testString.utf8)
        var output = [UInt8](repeating: 0, count: 32) // SHA256 is 32 bytes
        
        SHA256(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )
        
        // Known SHA256 hash for the test string
        let expectedHex = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        XCTAssertEqual(Data(output).hexString, expectedHex)
        
        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        SHA256(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &output
        )
        
        // Known SHA256 hash for empty string
        let emptyExpectedHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        XCTAssertEqual(Data(output).hexString, emptyExpectedHex)
    }
    
    // Test SHA384 hash function
    func testSHA384() {
        let input = Array(testString.utf8)
        var output = [UInt8](repeating: 0, count: 48) // SHA384 is 48 bytes
        
        SHA384(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )
        
        // Known SHA384 hash for the test string
        let expectedHex = "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
        XCTAssertEqual(Data(output).hexString, expectedHex)
        
        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        SHA384(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &output
        )
        
        // Known SHA384 hash for empty string
        let emptyExpectedHex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        XCTAssertEqual(Data(output).hexString, emptyExpectedHex)
    }
    
    // Test SHA512 hash function
    func testSHA512() {
        let input = Array(testString.utf8)
        var output = [UInt8](repeating: 0, count: 64) // SHA512 is 64 bytes
        
        SHA512(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )
        
        // Known SHA512 hash for the test string
        let expectedHex = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
        XCTAssertEqual(Data(output).hexString, expectedHex)
        
        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        SHA512(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &output
        )
        
        // Known SHA512 hash for empty string
        let emptyExpectedHex = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        XCTAssertEqual(Data(output).hexString, emptyExpectedHex)
    }

        // Helper function to convert hex string to bytes
    private func hexStringToBytes(_ hex: String) -> [UInt8] {
        var bytes = [UInt8]()
        var hex = hex
        while hex.count > 0 {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            if let val = UInt8(c, radix: 16) {
                bytes.append(val)
            }
        }
        return bytes
    }
    
    // Helper to convert bytes to hex string
    private func bytesToHexString(_ bytes: [UInt8]) -> String {
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    
    // Test data
    private let emptyString = ""
    private let testString1 = "hello world"
    private let testString2 = "The quick brown fox jumps over the lazy dog"
    
    // Known hashes for "hello world"
    private let MD5_hello = "5eb63bbbe01eeed093cb22bb8f5acdc3"
    private let SHA1_hello = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    private let SHA256_hello = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    private let SHA384_hello = "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
    private let SHA512_hello = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    
    // MARK: - Single-shot hash tests
    
    func testMD5SingleShot() {
        let input = testString1.data(using: .utf8)!
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { output.deallocate() }
        
        input.withUnsafeBytes { inputPtr in
            MD5(inputPointer: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                inputLength: input.count,
                outputPointer: output)
        }
        
        let result = bytesToHexString(Array(UnsafeBufferPointer(start: output, count: 16)))
        XCTAssertEqual(result, MD5_hello)
    }
    
    func testSHA1SingleShot() {
        let input = testString1.data(using: .utf8)!
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 20)
        defer { output.deallocate() }
        
        input.withUnsafeBytes { inputPtr in
            SHA1(inputPointer: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                 inputLength: input.count,
                 outputPointer: output)
        }
        
        let result = bytesToHexString(Array(UnsafeBufferPointer(start: output, count: 20)))
        XCTAssertEqual(result, SHA1_hello)
    }
    
    func testSHA256SingleShot() {
        let input = testString1.data(using: .utf8)!
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
        defer { output.deallocate() }
        
        input.withUnsafeBytes { inputPtr in
            SHA256(inputPointer: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                   inputLength: input.count,
                   outputPointer: output)
        }
        
        let result = bytesToHexString(Array(UnsafeBufferPointer(start: output, count: 32)))
        XCTAssertEqual(result, SHA256_hello)
    }
    
    // MARK: - Incremental hash tests
    
    func testMD5Incremental() {
        let hasher = NewMD5()
        defer { MD5Free(hasher) }
        
        // Check size
        XCTAssertEqual(MD5BSize(), 16)
        XCTAssertEqual(MD5BlockSize(), 64)
        
        // Write in chunks
        let part1 = "hello ".data(using: .utf8)!
        let part2 = "world".data(using: .utf8)!
        
        part1.withUnsafeBytes { ptr in
            MD5Write(hasher, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), part1.count)
        }
        
        part2.withUnsafeBytes { ptr in
            MD5Write(hasher, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), part2.count)
        }
        
        // Get sum
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { output.deallocate() }
        
        MD5Sum(hasher, output)
        
        let result = bytesToHexString(Array(UnsafeBufferPointer(start: output, count: 16)))
        XCTAssertEqual(result, MD5_hello)
    }
    
    func testSHA1Incremental() {
        let hasher = NewSHA1()
        defer { SHA1Free(hasher) }
        
        // Check size
        XCTAssertEqual(SHA1Size(), 20)
        XCTAssertEqual(SHA1BlockSize(), 64)
        
        // Write in chunks
        let part1 = "hello ".data(using: .utf8)!
        let part2 = "world".data(using: .utf8)!
        
        part1.withUnsafeBytes { ptr in
            SHA1Write(hasher, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), part1.count)
        }
        
        part2.withUnsafeBytes { ptr in
            SHA1Write(hasher, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), part2.count)
        }
        
        // Get sum
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 20)
        defer { output.deallocate() }
        
        SHA1Sum(hasher, output)
        
        let result = bytesToHexString(Array(UnsafeBufferPointer(start: output, count: 20)))
        XCTAssertEqual(result, SHA1_hello)
    }
    
    // MARK: - Reset and Copy tests
    
    func testMD5ResetAndCopy() {
        let hasher = NewMD5()
        defer { MD5Free(hasher) }
        
        // Write something
        let data = "hello ".data(using: .utf8)!
        data.withUnsafeBytes { ptr in
            MD5Write(hasher, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count)
        }
        
        // Create a copy
        let copy = MD5Copy(hasher)
        defer { MD5Free(copy) }
        
        // Continue writing to original
        let data2 = "world".data(using: .utf8)!
        data2.withUnsafeBytes { ptr in
            MD5Write(hasher, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), data2.count)
        }
        
        // Reset copy and write different data
        MD5Reset(copy)
        let data3 = "different".data(using: .utf8)!
        data3.withUnsafeBytes { ptr in
            MD5Write(copy, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), data3.count)
        }
        
        // Get original sum
        let output1 = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { output1.deallocate() }
        MD5Sum(hasher, output1)
        let result1 = bytesToHexString(Array(UnsafeBufferPointer(start: output1, count: 16)))
        
        // Get copy sum
        let output2 = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { output2.deallocate() }
        MD5Sum(copy, output2)
        let result2 = bytesToHexString(Array(UnsafeBufferPointer(start: output2, count: 16)))
        
        // Original should be "hello world" hash
        XCTAssertEqual(result1, MD5_hello)
        
        // Copy should be "different" hash
        XCTAssertEqual(result2, "55d99c20facde0a7a5ba589fd2aa5a71")
    }
    
    // MARK: - Additional hash algorithm tests
    
    func testSHA384() {
        let input = testString1.data(using: .utf8)!
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 48)
        defer { output.deallocate() }
        
        input.withUnsafeBytes { inputPtr in
            SHA384(inputPointer: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                   inputLength: input.count,
                   outputPointer: output)
        }
        
        let result = bytesToHexString(Array(UnsafeBufferPointer(start: output, count: 48)))
        XCTAssertEqual(result, SHA384_hello)
    }
    
    func testSHA512() {
        let input = testString1.data(using: .utf8)!
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        defer { output.deallocate() }
        
        input.withUnsafeBytes { inputPtr in
            SHA512(inputPointer: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                   inputLength: input.count,
                   outputPointer: output)
        }
        
        let result = bytesToHexString(Array(UnsafeBufferPointer(start: output, count: 64)))
        XCTAssertEqual(result, SHA512_hello)
    }
    
    // MARK: - Test with empty string
    
    func testEmptyStringHashes() {
        let input = emptyString.data(using: .utf8)!
        
        // MD5
        let md5Output = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { md5Output.deallocate() }
        
        input.withUnsafeBytes { inputPtr in
            MD5(inputPointer: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                inputLength: input.count,
                outputPointer: md5Output)
        }
        
        XCTAssertEqual(bytesToHexString(Array(UnsafeBufferPointer(start: md5Output, count: 16))), 
                      "d41d8cd98f00b204e9800998ecf8427e")
        
        // SHA1
        let sha1Output = UnsafeMutablePointer<UInt8>.allocate(capacity: 20)
        defer { sha1Output.deallocate() }
        
        input.withUnsafeBytes { inputPtr in
            SHA1(inputPointer: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                 inputLength: input.count,
                 outputPointer: sha1Output)
        }
        
        XCTAssertEqual(bytesToHexString(Array(UnsafeBufferPointer(start: sha1Output, count: 20))), 
                      "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }
}

// Helper extension to convert Data to hex string
extension Data {
    var hexString: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}
