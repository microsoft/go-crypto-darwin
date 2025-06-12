// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import Foundation

// MARK: - Data <-> Hex String Helpers (Shared Test Utilities)
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
