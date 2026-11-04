#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Resources/Info.plist)
ROOT=".build/dmg-root"
mkdir -p "$ROOT"
/usr/bin/ditto "dist/카카오 광고 정리.app" "$ROOT/카카오 광고 정리.app"
if [ ! -L "$ROOT/Applications" ]; then /bin/ln -s /Applications "$ROOT/Applications"; fi
/bin/cp Resources/설치안내.txt "$ROOT/설치안내.txt"
/usr/bin/hdiutil create -volname "카카오 광고 정리" -srcfolder "$ROOT" -ov -format UDZO "dist/NoAdKakao-$VERSION-arm64.dmg"
/usr/bin/hdiutil verify "dist/NoAdKakao-$VERSION-arm64.dmg"
(cd dist && /usr/bin/shasum -a 256 "NoAdKakao-$VERSION-arm64.dmg" > SHA256SUMS.txt)
