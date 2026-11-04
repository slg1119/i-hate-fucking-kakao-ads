#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist .build/module-cache
BUILD_DIR=$(/usr/bin/mktemp -d "$PWD/.build/app.XXXXXX")
trap '/bin/rm -rf "$BUILD_DIR"' EXIT
APP="$BUILD_DIR/카카오 광고 정리.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
/usr/bin/xcrun swiftc -module-cache-path .build/module-cache scripts/MakeIcon.swift -o .build/make-icon
.build/make-icon .build/AppIcon.iconset
/usr/bin/iconutil -c icns .build/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"
/usr/bin/xcrun swiftc -swift-version 5 -parse-as-library -O \
  -target arm64-apple-macosx14.0 -module-cache-path .build/module-cache \
  -framework SwiftUI -framework AppKit -framework CryptoKit \
  Sources/PatchCore.swift Sources/EngineTests.swift Sources/KakaoPatchApp.swift \
  -o "$APP/Contents/MacOS/NoAdKakao"
/usr/bin/ditto Resources/Info.plist "$APP/Contents/Info.plist"
/usr/bin/codesign --force --sign - --timestamp=none "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
if [ -d "dist/카카오 광고 정리.app" ]; then /bin/mv "dist/카카오 광고 정리.app" "$BUILD_DIR/previous.app"; fi
/bin/mv "$APP" "dist/카카오 광고 정리.app"
echo "dist/카카오 광고 정리.app"
