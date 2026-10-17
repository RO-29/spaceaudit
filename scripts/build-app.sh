#!/bin/sh
# Builds dist/SpaceAudit.app: a universal SwiftUI app with the universal spaceaudit CLI inside.
set -eu
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
APP=dist/SpaceAudit.app
LDFLAGS="-s -w -X github.com/RO-29/spaceaudit/internal/scan.Version=$VERSION"
mkdir -p dist/tmp "$APP/Contents/MacOS" "$APP/Contents/Resources"

GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o dist/tmp/spaceaudit-arm64 ./cmd/spaceaudit
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/tmp/spaceaudit-amd64 ./cmd/spaceaudit
lipo -create -output dist/spaceaudit dist/tmp/spaceaudit-arm64 dist/tmp/spaceaudit-amd64

for arch in arm64 x86_64; do
  swiftc -parse-as-library -O -target "$arch-apple-macos14" -framework SwiftUI -framework AppKit \
    macapp/SpaceAudit.swift -o "dist/tmp/SpaceAudit-$arch"
done
lipo -create -output "$APP/Contents/MacOS/SpaceAudit" dist/tmp/SpaceAudit-arm64 dist/tmp/SpaceAudit-x86_64
cp dist/spaceaudit "$APP/Contents/Resources/spaceaudit"
sed "s/__VERSION__/$VERSION/g" macapp/Info.plist > "$APP/Contents/Info.plist"
sh scripts/make-icon.sh "$APP/Contents/Resources/AppIcon.icns" || echo "icon skipped"
# A stable identity keeps privacy grants (Full Disk Access) across rebuilds; ad-hoc signing changes every build.
SIGN_ID="${SIGN_ID:-$(security find-identity -v -p codesigning 2>/dev/null | awk -F'"' '/Apple Development|Developer ID Application/ {print $2; exit}')}"
SIGN_ID="${SIGN_ID:--}"
codesign --force --sign "$SIGN_ID" --identifier io.github.ro-29.spaceaudit.cli "$APP/Contents/Resources/spaceaudit"
codesign --force --sign "$SIGN_ID" --identifier io.github.ro-29.spaceaudit.cli dist/spaceaudit
codesign --force --sign "$SIGN_ID" "$APP"
echo "Signed with: $SIGN_ID"
rm -rf dist/tmp
echo "Built $APP and dist/spaceaudit ($VERSION)"
