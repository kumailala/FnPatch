#!/usr/bin/env bash
# Builds FnPatch.dylib against the iOS SDK. Run on any macOS with Xcode.
set -euo pipefail
cd "$(dirname "$0")"

OUT="${1:-FnPatch.dylib}"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"

echo "SDK: $SDK"
echo "Sources: $(ls src/*.c | tr '\n' ' ')"

xcrun -sdk iphoneos clang \
  -arch arm64 \
  -dynamiclib \
  -O2 \
  -fobjc-arc \
  -fvisibility=hidden \
  -Wall -Wextra -Wno-unused-parameter \
  -Isrc \
  -isysroot "$SDK" \
  -miphoneos-version-min=15.0 \
  -install_name "@rpath/FnPatch.dylib" \
  -framework Foundation \
  -framework CoreFoundation \
  -framework Security \
  -framework UIKit \
  -o "$OUT" \
  src/*.c src/*.m

if command -v ldid >/dev/null 2>&1; then
  ldid -S "$OUT"
  echo "signed with ldid"
else
  codesign --force --sign - "$OUT"
  echo "ad-hoc signed with codesign"
fi

echo "built: $(pwd)/$OUT"
file "$OUT"
