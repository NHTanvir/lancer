#!/usr/bin/env bash
# Linux installer for Lancer (Ubuntu/Debian + generic Linux).
# Usage:
#   sudo ./install-linux.sh             # install to /usr/local/bin
#   sudo ./install-linux.sh --uninstall # remove installed binaries
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
DIST="dist/lancer-linux-x86_64/bin"

if [[ "${1:-}" == "--uninstall" ]]; then
    echo "Removing Lancer binaries from $BIN_DIR ..."
    for f in lancer lancer-api lancer-gui; do
        rm -f "$BIN_DIR/$f"
    done
    rm -f /usr/share/applications/lancer.desktop
    echo "Uninstalled."
    exit 0
fi

if [[ ! -d "$DIST" ]]; then
    echo "Build first: ./build-linux.sh"
    echo "Expected: $DIST"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo (writing to $BIN_DIR)."
    exit 1
fi

echo "Installing Lancer to $BIN_DIR ..."
install -m 0755 -d "$BIN_DIR"
for f in lancer lancer-api lancer-gui; do
    if [[ -f "$DIST/$f" ]]; then
        install -m 0755 "$DIST/$f" "$BIN_DIR/$f"
        echo "  + $BIN_DIR/$f"
    fi
done

# Desktop entry for the GUI
if [[ -f "$DIST/lancer-gui" ]]; then
    install -m 0644 -d /usr/share/applications
    cat > /usr/share/applications/lancer.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Lancer
GenericName=Web Security Testing Suite
Exec=lancer-gui
Categories=Development;Security;
Terminal=false
EOF
    echo "  + /usr/share/applications/lancer.desktop"
fi

echo
echo "Done. Run:"
echo "  lancer --help"
echo "  lancer-api --listen 127.0.0.1:9191 --project ./demo.lancer"
