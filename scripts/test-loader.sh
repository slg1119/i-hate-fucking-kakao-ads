#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build/loader-probe
/usr/bin/xcrun clang -dynamiclib Tests/loader-library.c -install_name @rpath/libNoAdKakaoProbe.dylib -o .build/loader-probe/libNoAdKakaoProbe.dylib
/usr/bin/xcrun clang Tests/loader-main.c -L.build/loader-probe -lNoAdKakaoProbe -Wl,-rpath,@executable_path -o .build/loader-probe/NoAdKakaoLoaderProbe
/usr/bin/codesign --force --sign - --timestamp=none .build/loader-probe/libNoAdKakaoProbe.dylib
/usr/bin/codesign --force --sign - --timestamp=none --options runtime --entitlements Tests/loader-entitlements.plist .build/loader-probe/NoAdKakaoLoaderProbe
.build/loader-probe/NoAdKakaoLoaderProbe
