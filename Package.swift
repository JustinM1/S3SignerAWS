// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "S3SignerAWS",
    platforms: [
        .macOS(.v10_14)
    ],
    products: [
        .library(name: "S3SignerAWS", targets: ["S3SignerAWS"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/open-crypto.git", from: "4.0.0-beta.2")
    ],
    targets: [
        .target(name: "S3SignerAWS", dependencies: ["OpenCrypto"], path: "Sources"),
        .testTarget(name: "S3SignerAWSTests", dependencies: ["S3SignerAWS"]),
    ]
)
