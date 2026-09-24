// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "AuthSessionPlugin",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "AuthSessionPlugin", type: .static, targets: ["AuthSessionPlugin"])
    ],
    targets: [
        .target(
            name: "AuthSessionPlugin",
            path: "Sources",
            linkerSettings: [.linkedFramework("AuthenticationServices")]
        )
    ]
)
