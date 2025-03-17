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
}

// Helper extension to convert Data to hex string
extension Data {
    var hexString: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}
