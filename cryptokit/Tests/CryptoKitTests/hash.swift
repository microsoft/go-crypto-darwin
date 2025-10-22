// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation
import XCTest

@testable import CryptoKitSrc

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
    let knownTestStringHashHex: String  // Using "hello world" for these wrappers
}

final class CryptoKitTests: XCTestCase {

    // MARK: - Properties for Existing Tests

    // Test string used in the original simple hash tests
    let simpleTestString = "The quick brown fox jumps over the lazy dog"
    let emptyString = ""  // Used in both sets of tests

    // MARK: - Existing Simple One-Shot Hash Function Tests

    // Test MD5 hash function (Simple API)
    func testMD5_SimpleAPI() {  // Renamed to avoid conflict
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 16)  // MD5 is 16 bytes

        MD5(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known MD5 hash for the test string (as hex)
        let expectedHex = "9e107d9d372bb6826bd81d3542a419d6"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        var emptyOutput = [UInt8](repeating: 0, count: 16)  // Re-declare for clarity
        MD5(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )

        // Known MD5 hash for empty string
        let emptyExpectedHex = "d41d8cd98f00b204e9800998ecf8427e"
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }

    // Test SHA1 hash function (Simple API)
    func testSHA1_SimpleAPI() {  // Renamed
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 20)  // SHA1 is 20 bytes

        SHA1(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known SHA1 hash for the test string
        let expectedHex = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

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
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }

    // Test SHA256 hash function (Simple API)
    func testSHA256_SimpleAPI() {  // Renamed
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 32)  // SHA256 is 32 bytes

        SHA256(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known SHA256 hash for the test string
        let expectedHex = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

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
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }

    // Test SHA384 hash function (Simple API)
    func testSHA384_SimpleAPI() {  // Renamed
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 48)  // SHA384 is 48 bytes

        SHA384(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known SHA384 hash for the test string
        let expectedHex =
            "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

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
        let emptyExpectedHex =
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }

    // Test SHA512 hash function (Simple API)
    func testSHA512_SimpleAPI() {  // Renamed
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 64)  // SHA512 is 64 bytes

        SHA512(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known SHA512 hash for the test string
        let expectedHex =
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        var emptyOutput = [UInt8](repeating: 0, count: 64)
        SHA512(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )

        // Known SHA512 hash for empty string
        let emptyExpectedHex =
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }

    // MARK: - SHA-3 Simple API Tests (macOS 26.0+)

    #if canImport(CryptoKit) && (swift(>=6.2) || (swift(>=5.9) && canImport(Keccak)))
    // Test SHA3-256 hash function (Simple API)
    @available(macOS 26.0, *)
    func testSHA3_256_SimpleAPI() {
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 32)  // SHA3-256 is 32 bytes

        SHA3_256(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known SHA3-256 hash for "The quick brown fox jumps over the lazy dog"
        let expectedHex = "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        var emptyOutput = [UInt8](repeating: 0, count: 32)
        SHA3_256(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )

        // Known SHA3-256 hash for empty string
        let emptyExpectedHex = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }

    // Test SHA3-384 hash function (Simple API)
    @available(macOS 26.0, *)
    func testSHA3_384_SimpleAPI() {
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 48)  // SHA3-384 is 48 bytes

        SHA3_384(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known SHA3-384 hash for "The quick brown fox jumps over the lazy dog"
        let expectedHex =
            "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        var emptyOutput = [UInt8](repeating: 0, count: 48)
        SHA3_384(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )

        // Known SHA3-384 hash for empty string
        let emptyExpectedHex =
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }

    // Test SHA3-512 hash function (Simple API)
    @available(macOS 26.0, *)
    func testSHA3_512_SimpleAPI() {
        let input = Array(simpleTestString.utf8)
        var output = [UInt8](repeating: 0, count: 64)  // SHA3-512 is 64 bytes

        SHA3_512(
            inputPointer: input,
            inputLength: input.count,
            outputPointer: &output
        )

        // Known SHA3-512 hash for "The quick brown fox jumps over the lazy dog"
        let expectedHex =
            "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450"
        XCTAssertEqual(Data(output).hexEncodedString(), expectedHex)

        // Test empty string
        let emptyInput = Array(emptyString.utf8)
        var emptyOutput = [UInt8](repeating: 0, count: 64)
        SHA3_512(
            inputPointer: emptyInput,
            inputLength: emptyInput.count,
            outputPointer: &emptyOutput
        )

        // Known SHA3-512 hash for empty string
        let emptyExpectedHex =
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        XCTAssertEqual(Data(emptyOutput).hexEncodedString(), emptyExpectedHex)
    }
    #endif

    func testHashFunctions() {
        let testString = "hello world"
        let testData = Data(testString.utf8)

        let functionsList: [HashingFunctions] = [
            HashingFunctions(
                name: "MD5",
                new: { hashNew(1) },
                write: { ptr, data, length in hashWrite(1, ptr, data, length) },
                sum: { ptr, out in hashSum(1, ptr, out) },
                reset: { ptr in hashReset(1, ptr) },
                copy: { ptr in hashCopy(1, ptr) },
                free: { ptr in hashFree(1, ptr) },
                size: { hashSize(1) },
                blockSize: { hashBlockSize(1) },
                expectedSize: Insecure.MD5.byteCount,
                expectedBlockSize: Insecure.MD5.blockByteCount,
                knownEmptyHashHex: "d41d8cd98f00b204e9800998ecf8427e",
                knownTestStringHashHex: "5eb63bbbe01eeed093cb22bb8f5acdc3"
            ),
            HashingFunctions(
                name: "SHA1",
                new: { hashNew(2) },
                write: { ptr, data, length in hashWrite(2, ptr, data, length) },
                sum: { ptr, out in hashSum(2, ptr, out) },
                reset: { ptr in hashReset(2, ptr) },
                copy: { ptr in hashCopy(2, ptr) },
                free: { ptr in hashFree(2, ptr) },
                size: { hashSize(2) },
                blockSize: { hashBlockSize(2) },
                expectedSize: Insecure.SHA1.byteCount,
                expectedBlockSize: Insecure.SHA1.blockByteCount,
                knownEmptyHashHex: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                knownTestStringHashHex: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
            ),
            HashingFunctions(
                name: "SHA256",
                new: { hashNew(3) },
                write: { ptr, data, length in hashWrite(3, ptr, data, length) },
                sum: { ptr, out in hashSum(3, ptr, out) },
                reset: { ptr in hashReset(3, ptr) },
                copy: { ptr in hashCopy(3, ptr) },
                free: { ptr in hashFree(3, ptr) },
                size: { hashSize(3) },
                blockSize: { hashBlockSize(3) },
                expectedSize: CryptoKit.SHA256.byteCount,
                expectedBlockSize: CryptoKit.SHA256.blockByteCount,
                knownEmptyHashHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                knownTestStringHashHex: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            ),
            HashingFunctions(
                name: "SHA384",
                new: { hashNew(4) },
                write: { ptr, data, length in hashWrite(4, ptr, data, length) },
                sum: { ptr, out in hashSum(4, ptr, out) },
                reset: { ptr in hashReset(4, ptr) },
                copy: { ptr in hashCopy(4, ptr) },
                free: { ptr in hashFree(4, ptr) },
                size: { hashSize(4) },
                blockSize: { hashBlockSize(4) },
                expectedSize: CryptoKit.SHA384.byteCount,
                expectedBlockSize: CryptoKit.SHA384.blockByteCount,
                knownEmptyHashHex:
                    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                knownTestStringHashHex:
                    "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
            ),
            HashingFunctions(
                name: "SHA512",
                new: { hashNew(5) },
                write: { ptr, data, length in hashWrite(5, ptr, data, length) },
                sum: { ptr, out in hashSum(5, ptr, out) },
                reset: { ptr in hashReset(5, ptr) },
                copy: { ptr in hashCopy(5, ptr) },
                free: { ptr in hashFree(5, ptr) },
                size: { hashSize(5) },
                blockSize: { hashBlockSize(5) },
                expectedSize: CryptoKit.SHA512.byteCount,
                expectedBlockSize: CryptoKit.SHA512.blockByteCount,
                knownEmptyHashHex:
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                knownTestStringHashHex:
                    "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
            ),
        ]

        // Add SHA-3 functions if available on macOS 26.0+
        var sha3FunctionsList: [HashingFunctions] = []

        #if canImport(CryptoKit) && (swift(>=6.2) || (swift(>=5.9) && canImport(Keccak)))
        if #available(macOS 26.0, *) {
            sha3FunctionsList = [
                HashingFunctions(
                    name: "SHA3-256",
                    new: { hashNew(6) },
                    write: { ptr, data, length in hashWrite(6, ptr, data, length) },
                    sum: { ptr, out in hashSum(6, ptr, out) },
                    reset: { ptr in hashReset(6, ptr) },
                    copy: { ptr in hashCopy(6, ptr) },
                    free: { ptr in hashFree(6, ptr) },
                    size: { hashSize(6) },
                    blockSize: { hashBlockSize(6) },
                    expectedSize: 32,  // SHA3-256 output size
                    expectedBlockSize: 136,  // SHA3-256 block size
                    knownEmptyHashHex: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                    knownTestStringHashHex: "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81d7a9ea90"  // "hello world"
                ),
                HashingFunctions(
                    name: "SHA3-384",
                    new: { hashNew(7) },
                    write: { ptr, data, length in hashWrite(7, ptr, data, length) },
                    sum: { ptr, out in hashSum(7, ptr, out) },
                    reset: { ptr in hashReset(7, ptr) },
                    copy: { ptr in hashCopy(7, ptr) },
                    free: { ptr in hashFree(7, ptr) },
                    size: { hashSize(7) },
                    blockSize: { hashBlockSize(7) },
                    expectedSize: 48,  // SHA3-384 output size
                    expectedBlockSize: 104,  // SHA3-384 block size
                    knownEmptyHashHex:
                        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
                    knownTestStringHashHex:
                        "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b"  // "hello world"
                ),
                HashingFunctions(
                    name: "SHA3-512",
                    new: { hashNew(8) },
                    write: { ptr, data, length in hashWrite(8, ptr, data, length) },
                    sum: { ptr, out in hashSum(8, ptr, out) },
                    reset: { ptr in hashReset(8, ptr) },
                    copy: { ptr in hashCopy(8, ptr) },
                    free: { ptr in hashFree(8, ptr) },
                    size: { hashSize(8) },
                    blockSize: { hashBlockSize(8) },
                    expectedSize: 64,  // SHA3-512 output size
                    expectedBlockSize: 72,  // SHA3-512 block size
                    knownEmptyHashHex:
                        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
                    knownTestStringHashHex:
                        "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a"  // "hello world"
                ),
            ]
        }
        #endif

        let allFunctionsList = functionsList + sha3FunctionsList

        for functions in allFunctionsList {
            let ptr = functions.new()
            defer { functions.free(ptr) }

            XCTAssertEqual(functions.size(), functions.expectedSize, "\(functions.name) size mismatch")
            XCTAssertEqual(
                functions.blockSize(),
                functions.expectedBlockSize,
                "\(functions.name) block size mismatch"
            )

            // Test empty hash
            let emptyOutput = UnsafeMutablePointer<UInt8>.allocate(capacity: functions.size())
            defer { emptyOutput.deallocate() }

            functions.sum(ptr, emptyOutput)
            XCTAssertEqual(
                Data(buffer: UnsafeBufferPointer(start: emptyOutput, count: functions.size())).hexEncodedString(),
                functions.knownEmptyHashHex,
                "\(functions.name) empty hash mismatch"
            )

            // Test hash with data
            functions.reset(ptr)
            testData.withUnsafeBytes { buffer in
                functions.write(ptr, buffer.baseAddress!.assumingMemoryBound(to: UInt8.self), buffer.count)
            }

            let output = UnsafeMutablePointer<UInt8>.allocate(capacity: functions.size())
            defer { output.deallocate() }

            functions.sum(ptr, output)
            XCTAssertEqual(
                Data(buffer: UnsafeBufferPointer(start: output, count: functions.size())).hexEncodedString(),
                functions.knownTestStringHashHex,
                "\(functions.name) hash mismatch"
            )

            // Test copy
            let copiedPtr = functions.copy(ptr)
            defer { functions.free(copiedPtr) }

            let copiedOutput = UnsafeMutablePointer<UInt8>.allocate(capacity: functions.size())
            defer { copiedOutput.deallocate() }

            functions.sum(copiedPtr, copiedOutput)
            XCTAssertEqual(
                Data(buffer: UnsafeBufferPointer(start: copiedOutput, count: functions.size())).hexEncodedString(),
                functions.knownTestStringHashHex,
                "\(functions.name) copied hash mismatch"
            )

            // Test reset and re-sum
            functions.reset(ptr)
            functions.sum(ptr, output)
            XCTAssertEqual(
                Data(buffer: UnsafeBufferPointer(start: output, count: functions.size())).hexEncodedString(),
                functions.knownEmptyHashHex,
                "\(functions.name) reset hash mismatch"
            )
        }
    }

}
