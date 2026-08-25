#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
OUTPUT="$ROOT/sdk/apple/Artifacts/CQuicp.xcframework"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/quicp-apple.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"

cd "$ROOT"
cargo rustc --release --locked --features ffi-c --crate-type staticlib \
    --target aarch64-apple-darwin
cargo rustc --release --locked --features ffi-c --crate-type staticlib \
    --target x86_64-apple-darwin
cargo rustc --release --locked --features ffi-c --crate-type staticlib \
    --target aarch64-apple-ios
cargo rustc --release --locked --features ffi-c --crate-type staticlib \
    --target aarch64-apple-ios-sim
cargo rustc --release --locked --features ffi-c --crate-type staticlib \
    --target x86_64-apple-ios

mkdir -p "$WORK/headers" "$ROOT/sdk/apple/Artifacts"
cp "$ROOT/include/quicp.h" "$WORK/headers/quicp.h"
cp "$ROOT/sdk/apple/CQuicp/module.modulemap" "$WORK/headers/module.modulemap"
lipo -create \
    "$ROOT/target/aarch64-apple-darwin/release/libquicp.a" \
    "$ROOT/target/x86_64-apple-darwin/release/libquicp.a" \
    -output "$WORK/libquicp-macos.a"
lipo -create \
    "$ROOT/target/aarch64-apple-ios-sim/release/libquicp.a" \
    "$ROOT/target/x86_64-apple-ios/release/libquicp.a" \
    -output "$WORK/libquicp-simulator.a"
rm -rf "$OUTPUT"
xcodebuild -create-xcframework \
    -library "$WORK/libquicp-macos.a" \
    -headers "$WORK/headers" \
    -library "$ROOT/target/aarch64-apple-ios/release/libquicp.a" \
    -headers "$WORK/headers" \
    -library "$WORK/libquicp-simulator.a" \
    -headers "$WORK/headers" \
    -output "$OUTPUT"
