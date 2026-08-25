// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "Quicp",
  platforms: [.iOS(.v15), .macOS(.v12)],
  products: [.library(name: "Quicp", targets: ["Quicp"])],
  targets: [
    .binaryTarget(name: "CQuicp", path: "Artifacts/CQuicp.xcframework"),
    .target(name: "Quicp", dependencies: ["CQuicp"]),
    .testTarget(name: "QuicpTests", dependencies: ["Quicp"]),
  ]
)
