#!/usr/bin/env bash
# Linux release build for Lancer (Ubuntu/Debian).
# Output: dist/lancer-linux-x86_64/ + .deb at dist/lancer_<version>_amd64.deb
#
# Prereqs (Ubuntu 22.04+):
#   sudo apt install -y build-essential pkg-config libssl-dev cmake
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#
set -euo pipefail

VERSION="$(grep -m1 '^version' Cargo.toml | head -1 | cut -d'"' -f2 || echo 0.1.0)"
DIST=dist/lancer-linux-x86_64
DEB=dist/lancer_${VERSION}_amd64.deb

echo "=== Building Svelte SPA ==="
pushd crates/lancer-gui/web > /dev/null
[ -d node_modules ] || npm install
npm run build
popd > /dev/null

echo "=== Building Lancer ${VERSION} (release) for Linux x86_64 ==="
cargo build --release --workspace --no-default-features --bins

rm -rf "$DIST"
mkdir -p "$DIST/bin"

cp target/release/lancer "$DIST/bin/" 2>/dev/null || true
cp target/release/lancer-api "$DIST/bin/" 2>/dev/null || true
cp target/release/lancer-gui "$DIST/bin/" 2>/dev/null || true
cp LICENSE "$DIST/" 2>/dev/null || true
cp README.md "$DIST/" 2>/dev/null || true

echo "=== Building .deb ==="
PKG="dist/lancer_${VERSION}_amd64"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/local/bin" "$PKG/usr/share/applications" "$PKG/usr/share/doc/lancer"

cp "$DIST/bin/"* "$PKG/usr/local/bin/" 2>/dev/null || true
chmod 0755 "$PKG/usr/local/bin/"* 2>/dev/null || true
cp LICENSE "$PKG/usr/share/doc/lancer/" 2>/dev/null || true
cp README.md "$PKG/usr/share/doc/lancer/" 2>/dev/null || true

cat > "$PKG/DEBIAN/control" <<EOF
Package: lancer
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Lancer maintainers <noreply@example.com>
Depends: libc6, libssl3 | libssl1.1
Description: Web application security testing suite
 Lancer is a Rust-based intercepting proxy, scanner, and toolset for
 web application security testing. Burp Suite feature-equivalent and
 then some.
EOF

cat > "$PKG/usr/share/applications/lancer.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Lancer
GenericName=Web Security Testing Suite
Exec=lancer-gui
Categories=Development;Security;
Terminal=false
EOF

dpkg-deb --build "$PKG" "$DEB"
rm -rf "$PKG"

echo "=== Done ==="
echo "Portable tree: $DIST"
echo "Debian pkg:    $DEB"
echo
echo "Install: sudo dpkg -i $DEB"
