# Apple SDK proof-verification download measurement

The updated production XCFramework ZIP is **64,100,888 bytes**, a decrease of
**7,236,603 bytes** from the unchanged baseline package. It therefore meets the
requirement that the actual SDK download increase remain below 500,000 bytes.
This result includes a release packaging improvement: removing local symbols
from the shipping static libraries while preserving their global symbols.

The isolated source change adds **662,369 bytes across all three Apple slices**
when both versions use the same improved packaging. That isolated increase is
above 500,000 bytes; the shipping package meets the download budget because
packaging saves more bytes than the proof integration adds.

## Exact artifact comparison

All sizes are bytes for the complete `DashSDKFFI.xcframework.zip`, including
iOS arm64, macOS arm64, and iOS simulator arm64, with the existing shielded wallet
feature enabled in both versions.

| Source | Packaging | ZIP bytes |
| --- | --- | ---: |
| Baseline | Original | 71,337,491 |
| Updated proof integration | Original | 72,065,916 |
| Baseline | Strip local symbols | 63,438,519 |
| Updated proof integration | Strip local symbols; actual new shipping package | 64,100,888 |

- Shipping change versus unchanged baseline: **−7,236,603 bytes**.
- Source change with identical stripping: **+662,369 bytes**.
- Source change with original packaging: **+728,425 bytes**.
- Packaging savings on the updated source: **−7,965,028 bytes**.

These measure complete SDK integration, including proof verification and seeds;
they do not measure proof response traffic, Android downloads, or final linked
application size. Per-slice raw and gzip measurements and exact archive SHA256
values are in [proof-size-measurements.json](proof-size-measurements.json).

## Source and build provenance

- Baseline: `64f94838d2e1f2fa2eecb890a7ff6f97efd265c6`.
- Updated implementation: `6babdb452c91b2f0ace8faa6d79b0e0f8a04fd7e`.
- Toolchain: Rust/Cargo 1.92.0; Xcode 26.6, build 17F113; macOS 26.5 arm64.
- Cargo profile: `release-ios`, optimization 3, fat LTO, one codegen unit,
  panic abort, symbol stripping.
- Deployment targets: iOS 17.0, simulator 17.0, macOS 15.0.
- Features: `shielded` in both versions.

For each source version, each target was built in a **separate Cargo invocation**,
matching `build_ios.sh`. Combining several `--target` arguments can change Cargo
feature unification and is not the basis of this comparison.

```bash
cargo build -p rs-unified-sdk-ffi --profile release-ios --target aarch64-apple-ios --features shielded
cargo build -p rs-unified-sdk-ffi --profile release-ios --target aarch64-apple-ios-sim --features shielded
cargo build -p rs-unified-sdk-ffi --profile release-ios --target aarch64-apple-darwin --features shielded
```

Each target's before/after pair used the same source path, toolchain, deployment
settings, and build options. Generated shipping headers and the module map were
included. `xcodebuild -create-xcframework` assembled the libraries in the shipping
order: iOS, macOS, simulator. The new release packaging runs `xcrun strip -x` on
each copied framework library. It leaves the original Cargo build outputs intact.
The ZIP command was:

```bash
ditto -c -k --sequesterRsrc --keepParent DashSDKFFI.xcframework DashSDKFFI.xcframework.zip
```

The frozen native source snapshot was checked against the implementation commit;
no Rust source or manifest mismatches remained. The JSON records source paths,
snapshot hash, shipping script hash, and exact measured archive hashes. Archive
timestamps and metadata are not deterministic, so these hashes identify measured
artifacts rather than promise identical hashes from future builds.

## Validation

All three release slices built successfully. Comparing the complete defined global
symbol multisets before and after stripping found no changes: 2,276 symbols on
iOS, 2,275 on macOS, and 2,275 on the simulator. The production packaging script
also completed successfully, and its shell syntax and ShellCheck checks passed.

A fresh Swift link against the final stripped production framework succeeded.
Eight selected runtime tests passed on macOS, covering default verified mainnet
and testnet constructors, identity key derivation/signing and binding rejection,
and signed Core transaction handling:

```bash
swift test --package-path packages/swift-sdk \
  --scratch-path /tmp/platform-mining-swift-runtime \
  --filter 'SDKMethodTests.testDefaultConstructorUsesVerifiedNetworkSeeds|IdentityResolverSignIntegrationTests|SignedCoreTransactionTests'
```

Related validation passed: 328 FFI unit tests with one ignored, native JNI
checking, four Kotlin lifecycle tests, and three Core proof tests each on native
and Node WASM. The Core tests include a real Core fixture and adversarial BLS
encoding/subgroup cases. The full Swift suite was not run, and no physical iOS
device runtime test was performed.

Exact local artifacts and measurement metadata are retained under
`/tmp/platform-mining-ios-measurements`. The shipping archive is
`production-stripped-full.xcframework.zip`; its SHA256 is
`a0a3c3cc3795b55aedd26ea1749a458b6174c39449d8843f7cb05c212149b40e`.
