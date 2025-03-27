// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import XCTest
import Foundation
import CryptoKit
@testable import CryptoKitSrc // Make internal/public functions from CryptoKitSrc available

// MARK: - Data <-> Hex String Helpers (Combined & Enhanced)
extension Data {
    /// Returns a hexadecimal string representation of the data.
    func hexEncodedString() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
    
    /// Initializes Data from a hexadecimal string representation.
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            if let b = UInt8(hexString[index..<nextIndex], radix: 16) {
                data.append(b)
            } else {
                // Handle potential invalid characters or odd length
                return nil
            }
            index = nextIndex
        }
        // Ensure the entire string was consumed (no trailing characters)
        guard index == hexString.endIndex else { return nil }
        self.init(data)
    }
    
    // Keep existing computed property if needed elsewhere, but prefer function for clarity
    var hexString: String {
        return self.hexEncodedString()
    }
}

// MARK: - Hash Function Configuration Structure (for C-Style Wrappers)
// Placed outside the class for better organization, or could be nested inside.
struct HashingFunctions {
    let name: String
    let new: () -> UnsafeMutableRawPointer
    let write: (UnsafeMutableRawPointer, UnsafePointer<UInt8>, Int) -> Void
    let sum: (UnsafeMutableRawPointer, UnsafeMutablePointer<UInt8>) -> Void
    let reset: (UnsafeMutableRawPointer) -> Void
    let copy: (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer
    let free: (UnsafeMutableRawPointer) -> Void
    let size: () -> Int
    let blockSize: () -> Int
    
    // Expected values for verification
    let expectedSize: Int
    let expectedBlockSize: Int
    let knownEmptyHashHex: String
    let knownTestStringHashHex: String // Using "hello world" for these wrappers
}


final class CryptoKitTests: XCTestCase {
    
    // MARK: - Properties for Existing Tests
    
    // Test string used in the original simple hash tests
    let simpleTestString = "The quick brown fox jumps over the lazy dog"
    let emptyString = "" // Used in both sets of tests
    
    // MARK: - Existing Simple One-Shot Hash Function Tests
    
    // Test MD5 hash function (Simple API)
    func testMD5_SimpleAPI() { // Renamed to avoid conflict
        let input = Array(simpleTestString.utf8)
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
        var emptyOutput = [UInt8](repeating: 0, count: 16) // Re-declare for clarity
        MD5(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )
        
        // Known MD5 hash for empty string
        let emptyExpectedHex = "d41d8cd98f00b204e9800998ecf8427e"
        XCTAssertEqual(Data(emptyOutput).hexString, emptyExpectedHex)
    }
    
    // Test SHA1 hash function (Simple API)
    func testSHA1_SimpleAPI() { // Renamed
        let input = Array(simpleTestString.utf8)
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
        var emptyOutput = [UInt8](repeating: 0, count: 20)
        SHA1(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )
        
        // Known SHA1 hash for empty string
        let emptyExpectedHex = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        XCTAssertEqual(Data(emptyOutput).hexString, emptyExpectedHex)
    }
    
    // Test SHA256 hash function (Simple API)
    func testSHA256_SimpleAPI() { // Renamed
        let input = Array(simpleTestString.utf8)
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
        var emptyOutput = [UInt8](repeating: 0, count: 32)
        SHA256(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )
        
        // Known SHA256 hash for empty string
        let emptyExpectedHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        XCTAssertEqual(Data(emptyOutput).hexString, emptyExpectedHex)
    }
    
    // Test SHA384 hash function (Simple API)
    func testSHA384_SimpleAPI() { // Renamed
        let input = Array(simpleTestString.utf8)
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
        var emptyOutput = [UInt8](repeating: 0, count: 48)
        SHA384(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )
        
        // Known SHA384 hash for empty string
        // Correction: Original code had a typo in the empty hash for SHA384 (last digit was b instead of 4)
        let emptyExpectedHex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        XCTAssertEqual(Data(emptyOutput).hexString, emptyExpectedHex)
    }
    
    // Test SHA512 hash function (Simple API)
    func testSHA512_SimpleAPI() { // Renamed
        let input = Array(simpleTestString.utf8)
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
        var emptyOutput = [UInt8](repeating: 0, count: 64)
        SHA512(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )
        
        // Known SHA512 hash for empty string
        let emptyExpectedHex = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        XCTAssertEqual(Data(emptyOutput).hexString, emptyExpectedHex)
    }


    // MARK: - === C-Style Wrapper Function Tests ===

    // MARK: - Properties & Configurations for Wrapper Tests
    
    // Test string used for C-Style wrapper tests
    static let wrapperTestString = "hello world"
    static let wrapperTestStringData = wrapperTestString.data(using: .utf8)!
    static let emptyData = Data() // Used by both sets

    // Algorithm Configurations for C-Style Wrappers
    // (Assumes the @_cdecl functions NewMD5, MD5Write etc. are defined and accessible)
    static let md5Config = HashingFunctions(
        name: "MD5_Wrapper", new: NewMD5, write: MD5Write, sum: MD5Sum, reset: MD5Reset, copy: MD5Copy, free: MD5Free, size: MD5Size, blockSize: MD5BlockSize,
        expectedSize: 16, expectedBlockSize: 64,
        knownEmptyHashHex: "d41d8cd98f00b204e9800998ecf8427e",
        knownTestStringHashHex: "5eb63bbbe01eeed093cb22bb8f5acdc3" // "hello world"
    )

    static let sha1Config = HashingFunctions(
        name: "SHA1_Wrapper", new: NewSHA1, write: SHA1Write, sum: SHA1Sum, reset: SHA1Reset, copy: SHA1Copy, free: SHA1Free, size: SHA1Size, blockSize: SHA1BlockSize,
        expectedSize: 20, expectedBlockSize: 64,
        knownEmptyHashHex: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        knownTestStringHashHex: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" // "hello world"
    )

    static let sha256Config = HashingFunctions(
        name: "SHA256_Wrapper", new: NewSHA256, write: SHA256Write, sum: SHA256Sum, reset: SHA256Reset, copy: SHA256Copy, free: SHA256Free, size: SHA256Size, blockSize: SHA256BlockSize,
        expectedSize: 32, expectedBlockSize: 64,
        knownEmptyHashHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        knownTestStringHashHex: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" // "hello world"
    )
    
    static let sha384Config = HashingFunctions(
        name: "SHA384_Wrapper", new: NewSHA384, write: SHA384Write, sum: SHA384Sum, reset: SHA384Reset, copy: SHA384Copy, free: SHA384Free, size: SHA384Size, blockSize: SHA384BlockSize,
        expectedSize: 48, expectedBlockSize: 128,
        knownEmptyHashHex: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        knownTestStringHashHex: "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd" // "hello world"
    )

    static let sha512Config = HashingFunctions(
        name: "SHA512_Wrapper", new: NewSHA512, write: SHA512Write, sum: SHA512Sum, reset: SHA512Reset, copy: SHA512Copy, free: SHA512Free, size: SHA512Size, blockSize: SHA512BlockSize,
        expectedSize: 64, expectedBlockSize: 128,
        knownEmptyHashHex: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        knownTestStringHashHex: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f" // "hello world"
    )
    
    static let allWrapperConfigs = [md5Config, sha1Config, sha256Config, sha384Config, sha512Config]

    // MARK: - Generic Helper Methods for Wrapper Tests
    
    func calculateHash(for data: Data, using functions: HashingFunctions) -> Data {
        let ptr = functions.new()
        defer { functions.free(ptr) }
        writeData(data, to: ptr, using: functions)
        return getSum(from: ptr, using: functions)
    }
    
    func getSum(from ptr: UnsafeMutableRawPointer, using functions: HashingFunctions) -> Data {
        let outputSize = functions.size()
        // Check size consistency within the helper for robustness
        XCTAssertEqual(outputSize, functions.expectedSize, "\(functions.name): size() returned unexpected value (\(outputSize) vs expected \(functions.expectedSize)).")
        guard outputSize == functions.expectedSize else {
             // Avoid buffer overflow if size is wrong
            XCTFail("\(functions.name): Aborting sum calculation due to size mismatch.")
            return Data() // Return empty data on critical failure
        }
        var outputBuffer = [UInt8](repeating: 0, count: outputSize)
        outputBuffer.withUnsafeMutableBytes { rawMutableBufferPointer in
            let outputPtr = rawMutableBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            functions.sum(ptr, outputPtr)
        }
        return Data(outputBuffer)
    }

    func writeData(_ data: Data, to ptr: UnsafeMutableRawPointer, using functions: HashingFunctions) {
        data.withUnsafeBytes { rawBufferPointer in
            let count = rawBufferPointer.count
            let baseAddress = rawBufferPointer.baseAddress
            // Handle empty data case explicitly by passing a potentially null pointer but with count 0
            let unsafePointer = baseAddress?.assumingMemoryBound(to: UInt8.self) ?? UnsafePointer<UInt8>(bitPattern: 0)!
            functions.write(ptr, unsafePointer, count)
        }
    }

    // MARK: - Wrapper Tests Grouped by Functionality

    func testWrapper_BasicHashing() {
        for config in Self.allWrapperConfigs {
            // Test empty string
            let emptyResult = calculateHash(for: Self.emptyData, using: config)
            XCTAssertEqual(emptyResult.hexEncodedString(), config.knownEmptyHashHex, "\(config.name): Empty string hash mismatch")

            // Test known string ("hello world")
            let testStringResult = calculateHash(for: Self.wrapperTestStringData, using: config)
            XCTAssertEqual(testStringResult.hexEncodedString(), config.knownTestStringHashHex, "\(config.name): '\(Self.wrapperTestString)' hash mismatch")
        }
    }
    
    func testWrapper_MultipleWrites() {
        let part1 = "hello "
        let part2 = "world"
        let data1 = part1.data(using: .utf8)!
        let data2 = part2.data(using: .utf8)!

        for config in Self.allWrapperConfigs {
            let ptr = config.new()
            defer { config.free(ptr) }

            writeData(data1, to: ptr, using: config)
            writeData(data2, to: ptr, using: config)

            let resultData = getSum(from: ptr, using: config)
            XCTAssertEqual(resultData.hexEncodedString(), config.knownTestStringHashHex, "\(config.name): Multiple writes hash mismatch")
        }
    }

    func testWrapper_Reset() {
        for config in Self.allWrapperConfigs {
            let ptr = config.new()
            defer { config.free(ptr) }

            writeData("initial data".data(using: .utf8)!, to: ptr, using: config) // Write something
            config.reset(ptr)                                                    // Reset
            // After reset, it should behave as if new, so hashing empty data should yield empty hash
            writeData(Self.emptyData, to: ptr, using: config)                      

            let resultData = getSum(from: ptr, using: config)
            XCTAssertEqual(resultData.hexEncodedString(), config.knownEmptyHashHex, "\(config.name): Hash after reset + empty write mismatch")
            
            // Optional: Write test string after reset to double check
            config.reset(ptr)
            writeData(Self.wrapperTestStringData, to: ptr, using: config)
            let resultData2 = getSum(from: ptr, using: config)
             XCTAssertEqual(resultData2.hexEncodedString(), config.knownTestStringHashHex, "\(config.name): Hash after reset + '\(Self.wrapperTestString)' write mismatch")
        }
    }

    func testWrapper_Copy() {
        let initialData = "Initial ".data(using: .utf8)!
        let originalExtraData = "Original Extra".data(using: .utf8)!
        let copiedExtraData = "Copied Extra".data(using: .utf8)!
        
        let fullOriginalData = initialData + originalExtraData // "Initial Original Extra"
        let fullCopiedData = initialData + copiedExtraData   // "Initial Copied Extra"

        for config in Self.allWrapperConfigs {
            let originalPtr = config.new()
            defer { config.free(originalPtr) }

            writeData(initialData, to: originalPtr, using: config)

            let copiedPtr = config.copy(originalPtr) // Create copy *after* initial write
            defer { config.free(copiedPtr) } 

            // Write different data to original and copy *after* copying
            writeData(originalExtraData, to: originalPtr, using: config)
            writeData(copiedExtraData, to: copiedPtr, using: config)

            // Get final sums
            let originalResult = getSum(from: originalPtr, using: config)
            let copiedResult = getSum(from: copiedPtr, using: config)

            // Calculate expected results directly for comparison
            let expectedOriginal = calculateHash(for: fullOriginalData, using: config)
            let expectedCopied = calculateHash(for: fullCopiedData, using: config)

            XCTAssertEqual(originalResult, expectedOriginal, "\(config.name): Original hash after copy is incorrect.")
            XCTAssertEqual(copiedResult, expectedCopied, "\(config.name): Copied hash is incorrect.")
            XCTAssertNotEqual(originalResult, copiedResult, "\(config.name): Original and Copied hashes should differ.")
        }
    }
    
    func testWrapper_Constants() {
         for config in Self.allWrapperConfigs {
             XCTAssertEqual(config.size(), config.expectedSize, "\(config.name): size() constant mismatch.")
             XCTAssertEqual(config.blockSize(), config.expectedBlockSize, "\(config.name): blockSize() constant mismatch.")
         }
     }
     
     func testWrapper_Lifecycle() {
         for config in Self.allWrapperConfigs {
             let ptr = config.new()
             XCTAssertNotNil(ptr, "\(config.name): new() returned nil")
             // Simple check to ensure free doesn't crash (passes if no crash)
             config.free(ptr)
         }
     }
}
