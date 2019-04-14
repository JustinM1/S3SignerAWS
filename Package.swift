// swift-tools-version:5.0
import PackageDescription

let package = Package(
  name: "S3SignerAWS",
  products: [
    .library(name: "S3SignerAWS", targets: ["S3SignerAWS"]),
  ],
  dependencies: [
    .package(url: "https://github.com/vapor/crypto.git", .upToNextMinor(from: "3.3.0")),
  ],
  targets: [
    .target(name: "S3SignerAWS", dependencies: ["Crypto"], path: "Sources"),
    .testTarget(name: "S3SignerAWSTests", dependencies: ["S3SignerAWS"]),
  ]
)
