// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.
import PackageDescription
let package = Package(
    name: "eudiWalletOidcIos",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "eudiWalletOidcIos",
            targets: ["eudiWalletOidcIos"]),
    ],
    dependencies: [
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", from: "2.1.11"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.1"),
        .package(url: "https://github.com/decentralised-dataexchange/PresentationExchangeSdkiOS.git", .upToNextMajor(from: "2024.11.1")),
        .package(url: "https://github.com/airsidemobile/JOSESwift.git", from: "2.3.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from:"3.5.2"),
        .package(url: "https://github.com/niscy-eudiw/SwiftCBOR.git", from: "0.5.7"),
        .package(url: "https://github.com/1024jp/GzipSwift", from: "6.0.0")
    ],
    targets: [
        .target(
            name: "eudiWalletOidcIos",
            dependencies: ["Base58Swift", "CryptoSwift", "PresentationExchangeSdkiOS", "JOSESwift", "SwiftCBOR", .product(name: "Crypto", package: "swift-crypto"), .product(name: "Gzip", package: "GzipSwift")],
            path: "Sources"),
        .testTarget(
            name: "eudi-wallet-oidc-iosTests",
            dependencies: ["eudiWalletOidcIos"]),
    ]
)
