// swift-tools-version: 5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoKitSrc",
    platforms: [
        .macOS(.v11),
        .iOS(.v14),
    ],
    products: [
        .library(name: "CryptoKitSrc", type: .static, targets: ["CryptoKitSrc"])
    ],
    targets: [
        .target(
            name: "CryptoKitSrc"
        ),
        .testTarget(
            name: "CryptoKitTests",
            dependencies: ["CryptoKitSrc"]
        ),
    ]
)
