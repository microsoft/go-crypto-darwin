// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import CryptoKit
import Foundation
import XCTest

@testable import CryptoKitSrc

// MARK: - HMAC Function Configuration Structure
struct HMACFunctions {
    let name: String
    let hashFunction: Int32
    let initHMAC: (UnsafePointer<UInt8>, Int) -> UnsafeMutableRawPointer
    let update: (UnsafeMutableRawPointer, UnsafePointer<UInt8>, Int) -> Void
    let finalize: (UnsafeMutableRawPointer, UnsafeMutablePointer<UInt8>) -> Void
    let reset: (UnsafeMutableRawPointer, UnsafePointer<UInt8>, Int) -> Void
    let copy: (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer
    let free: (UnsafeMutableRawPointer) -> Void
    let size: () -> Int

    // Expected values for verification
    let expectedSize: Int
    let knownEmptyKeyHMACHex: String  // HMAC with empty key and empty message
    let knownTestKeyMessageHMACHex: String  // HMAC with "key" and "hello world"
}

class HMACTests: XCTestCase {

    // MARK: - Properties for Tests
    let testKey = "key"
    let testMessage = "hello world"
    let emptyKey = ""
    let emptyMessage = ""
    // MARK: - Simple HMAC Tests (Basic API)
    func testHMAC_MD5_Simple() {
        runSimpleHMACTest(hashFunction: 1, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA1_Simple() {
        runSimpleHMACTest(hashFunction: 2, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA256_Simple() {
        runSimpleHMACTest(hashFunction: 3, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA384_Simple() {
        runSimpleHMACTest(hashFunction: 4, key: "secret", message: "Hello, world!")
    }

    func testHMAC_SHA512_Simple() {
        runSimpleHMACTest(hashFunction: 5, key: "secret", message: "Hello, world!")
    }

    private func runSimpleHMACTest(hashFunction: Int32, key: String, message: String) {
        let keyData = key.data(using: .utf8)!
        let messageData = message.data(using: .utf8)!

        let keyPointer = keyData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }
        let hmacPointer = initHMAC(hashFunction, keyPointer, keyData.count)
        defer { freeHMAC(hashFunction, hmacPointer) }

        let messagePointer = messageData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }
        updateHMAC(hashFunction, hmacPointer, messagePointer, messageData.count)

        let outputSize = getHMACOutputSize(hashFunction)
        var output = [UInt8](repeating: 0, count: outputSize)
        finalizeHMAC(hashFunction, hmacPointer, &output)

        XCTAssertFalse(output.allSatisfy { $0 == 0 }, "HMAC output should not be all zeros")
    }

    // MARK: - Comprehensive HMAC Function Tests (Advanced API)
    func testHMACFunctions() {
        let testKeyData = Data(testKey.utf8)
        let testMessageData = Data(testMessage.utf8)
        let emptyKeyData = Data(emptyKey.utf8)
        let emptyMessageData = Data(emptyMessage.utf8)

        let functionsList: [HMACFunctions] = [
            HMACFunctions(
                name: "HMAC-MD5",
                hashFunction: 1,
                initHMAC: { keyPtr, keyLen in initHMAC(1, keyPtr, keyLen) },
                update: { ptr, data, length in updateHMAC(1, ptr, data, length) },
                finalize: { ptr, out in finalizeHMAC(1, ptr, out) },
                reset: { ptr, keyPtr, keyLen in resetHMAC(1, ptr, keyPtr, keyLen) },
                copy: { ptr in copyHMAC(1, ptr) },
                free: { ptr in freeHMAC(1, ptr) },
                size: { hmacSize(1) },
                expectedSize: Insecure.MD5.byteCount,
                knownEmptyKeyHMACHex: "74e6f7298a9c2d168935f58c001bad88",  // HMAC-MD5("", "")
                knownTestKeyMessageHMACHex: "ae92cf51adf91130130aefc2b39a7595"  // HMAC-MD5("key", "hello world") - Swift actual output
            ),
            HMACFunctions(
                name: "HMAC-SHA1",
                hashFunction: 2,
                initHMAC: { keyPtr, keyLen in initHMAC(2, keyPtr, keyLen) },
                update: { ptr, data, length in updateHMAC(2, ptr, data, length) },
                finalize: { ptr, out in finalizeHMAC(2, ptr, out) },
                reset: { ptr, keyPtr, keyLen in resetHMAC(2, ptr, keyPtr, keyLen) },
                copy: { ptr in copyHMAC(2, ptr) },
                free: { ptr in freeHMAC(2, ptr) },
                size: { hmacSize(2) },
                expectedSize: Insecure.SHA1.byteCount,
                knownEmptyKeyHMACHex: "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",  // HMAC-SHA1("", "")
                knownTestKeyMessageHMACHex: "34dd234b92683593560528f6193ea68c8005f615"  // HMAC-SHA1("key", "hello world") - Swift actual output
            ),
            HMACFunctions(
                name: "HMAC-SHA256",
                hashFunction: 3,
                initHMAC: { keyPtr, keyLen in initHMAC(3, keyPtr, keyLen) },
                update: { ptr, data, length in updateHMAC(3, ptr, data, length) },
                finalize: { ptr, out in finalizeHMAC(3, ptr, out) },
                reset: { ptr, keyPtr, keyLen in resetHMAC(3, ptr, keyPtr, keyLen) },
                copy: { ptr in copyHMAC(3, ptr) },
                free: { ptr in freeHMAC(3, ptr) },
                size: { hmacSize(3) },
                expectedSize: CryptoKit.SHA256.byteCount,
                knownEmptyKeyHMACHex: "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",  // HMAC-SHA256("", "")
                knownTestKeyMessageHMACHex: "0ba06f1f9a6300461e43454535dc3c4223e47b1d357073d7536eae90ec095be1"  // HMAC-SHA256("key", "hello world") - Swift actual output
            ),
            HMACFunctions(
                name: "HMAC-SHA384",
                hashFunction: 4,
                initHMAC: { keyPtr, keyLen in initHMAC(4, keyPtr, keyLen) },
                update: { ptr, data, length in updateHMAC(4, ptr, data, length) },
                finalize: { ptr, out in finalizeHMAC(4, ptr, out) },
                reset: { ptr, keyPtr, keyLen in resetHMAC(4, ptr, keyPtr, keyLen) },
                copy: { ptr in copyHMAC(4, ptr) },
                free: { ptr in freeHMAC(4, ptr) },
                size: { hmacSize(4) },
                expectedSize: CryptoKit.SHA384.byteCount,
                knownEmptyKeyHMACHex:
                    "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc",  // HMAC-SHA384("", "")
                knownTestKeyMessageHMACHex:
                    "b7e365fa38bb22d6553614a63095564a0411866e65aac7b835d02d0b24245f4dc48696c9d970ac20f24105be7dc60133"  // HMAC-SHA384("key", "hello world")
            ),
            HMACFunctions(
                name: "HMAC-SHA512",
                hashFunction: 5,
                initHMAC: { keyPtr, keyLen in initHMAC(5, keyPtr, keyLen) },
                update: { ptr, data, length in updateHMAC(5, ptr, data, length) },
                finalize: { ptr, out in finalizeHMAC(5, ptr, out) },
                reset: { ptr, keyPtr, keyLen in resetHMAC(5, ptr, keyPtr, keyLen) },
                copy: { ptr in copyHMAC(5, ptr) },
                free: { ptr in freeHMAC(5, ptr) },
                size: { hmacSize(5) },
                expectedSize: CryptoKit.SHA512.byteCount,
                knownEmptyKeyHMACHex:
                    "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",  // HMAC-SHA512("", "")
                knownTestKeyMessageHMACHex:
                    "ea0625a5ff1cd1653a327f8a4ae2f478fc51405c73ddac3a8a05a7a810310a6a14d7c8b4d284013493a6016ecadc772cfd98ed6cbe745949c5e6119fafb63b54"  // HMAC-SHA512("key", "hello world")
            ),
        ]

        for functions in functionsList {
            // Test size function
            XCTAssertEqual(functions.size(), functions.expectedSize, "\(functions.name) size mismatch")

            // Test empty key and empty message HMAC
            emptyKeyData.withUnsafeBytes { emptyKeyBytes in
                emptyMessageData.withUnsafeBytes { emptyMessageBytes in
                    let emptyKeyPtr = emptyKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    let emptyPtr = functions.initHMAC(emptyKeyPtr, emptyKeyData.count)
                    defer { functions.free(emptyPtr) }

                    let emptyMessagePtr = emptyMessageBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    functions.update(emptyPtr, emptyMessagePtr, emptyMessageData.count)

                    let emptyOutput = UnsafeMutablePointer<UInt8>.allocate(capacity: functions.size())
                    defer { emptyOutput.deallocate() }

                    functions.finalize(emptyPtr, emptyOutput)
                    XCTAssertEqual(
                        Data(buffer: UnsafeBufferPointer(start: emptyOutput, count: functions.size()))
                            .hexEncodedString(),
                        functions.knownEmptyKeyHMACHex,
                        "\(functions.name) empty key/message HMAC mismatch"
                    )
                }
            }

            // Test with test key and message
            testKeyData.withUnsafeBytes { testKeyBytes in
                testMessageData.withUnsafeBytes { testMessageBytes in
                    let testKeyPtr = testKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    let testPtr = functions.initHMAC(testKeyPtr, testKeyData.count)
                    defer { functions.free(testPtr) }

                    let testMessagePtr = testMessageBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    functions.update(testPtr, testMessagePtr, testMessageData.count)

                    // Test copy functionality (must be done BEFORE finalize)
                    let copyPtr = functions.copy(testPtr)
                    defer { functions.free(copyPtr) }

                    let testOutput = UnsafeMutablePointer<UInt8>.allocate(capacity: functions.size())
                    defer { testOutput.deallocate() }

                    functions.finalize(testPtr, testOutput)
                    XCTAssertEqual(
                        Data(buffer: UnsafeBufferPointer(start: testOutput, count: functions.size()))
                            .hexEncodedString(),
                        functions.knownTestKeyMessageHMACHex,
                        "\(functions.name) test key/message HMAC mismatch"
                    )

                    let copyOutput = UnsafeMutablePointer<UInt8>.allocate(capacity: functions.size())
                    defer { copyOutput.deallocate() }

                    functions.finalize(copyPtr, copyOutput)
                    XCTAssertEqual(
                        Data(buffer: UnsafeBufferPointer(start: copyOutput, count: functions.size()))
                            .hexEncodedString(),
                        functions.knownTestKeyMessageHMACHex,
                        "\(functions.name) copied HMAC mismatch"
                    )

                    // Test reset functionality (use a fresh context)
                    emptyKeyData.withUnsafeBytes { emptyKeyBytes in
                        emptyMessageData.withUnsafeBytes { emptyMessageBytes in
                            let resetPtr = functions.initHMAC(testKeyPtr, testKeyData.count)
                            defer { functions.free(resetPtr) }

                            functions.update(resetPtr, testMessagePtr, testMessageData.count)

                            let emptyKeyPtr = emptyKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                            functions.reset(resetPtr, emptyKeyPtr, emptyKeyData.count)

                            let emptyMessagePtr = emptyMessageBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                            functions.update(resetPtr, emptyMessagePtr, emptyMessageData.count)

                            let resetOutput = UnsafeMutablePointer<UInt8>.allocate(capacity: functions.size())
                            defer { resetOutput.deallocate() }

                            functions.finalize(resetPtr, resetOutput)
                            XCTAssertEqual(
                                Data(buffer: UnsafeBufferPointer(start: resetOutput, count: functions.size()))
                                    .hexEncodedString(),
                                functions.knownEmptyKeyHMACHex,
                                "\(functions.name) reset HMAC mismatch"
                            )
                        }
                    }
                }
            }
        }
    }

    // MARK: - Helper Functions
    private func getHMACOutputSize(_ hashFunction: Int32) -> Int {
        switch hashFunction {
        case 1: return 16  // MD5
        case 2: return 20  // SHA-1
        case 3: return 32  // SHA-256
        case 4: return 48  // SHA-384
        case 5: return 64  // SHA-512
        default: fatalError("Unsupported hash function")
        }
    }
}
