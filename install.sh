#!/bin/sh
set -e

REPO="effront/OhmZ"
INSTALL_DIR="/usr/local/bin"

echo "  OhmZ Installer"
echo ""

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_SUFFIX="x86_64" ;;
    aarch64) ARCH_SUFFIX="aarch64" ;;
    arm64)   ARCH_SUFFIX="aarch64" ;;
    *) echo "error: unsupported architecture: $ARCH"; exit 1 ;;
esac

# Detect OS
OS=$(uname -s)
case "$OS" in
    Linux) OS_SUFFIX="linux" ;;
    *) echo "error: unsupported OS: $OS (only Linux supported)"; exit 1 ;;
esac

# Get latest version
echo "Fetching latest release..."
VERSION=$(curl -sI "https://github.com/$REPO/releases/latest" | grep -i '^location:' | sed 's/.*tag\///' | tr -d '\r\n')
if [ -z "$VERSION" ]; then
    echo "error: could not determine latest version"
    exit 1
fi
echo "Latest version: $VERSION"

# Download
URL="https://github.com/$REPO/releases/download/$VERSION/ohmz-${OS_SUFFIX}-${ARCH_SUFFIX}.tar.gz"
echo "Downloading $URL..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -sL "$URL" -o "$TMPDIR/ohmz.tar.gz"
tar xzf "$TMPDIR/ohmz.tar.gz" -C "$TMPDIR"

# Install
if [ -w "$INSTALL_DIR" ]; then
    cp "$TMPDIR/ohmz" "$INSTALL_DIR/ohmz"
else
    echo "Installing to $INSTALL_DIR (requires sudo)..."
    sudo cp "$TMPDIR/ohmz" "$INSTALL_DIR/ohmz"
fi
chmod +x "$INSTALL_DIR/ohmz"

echo ""
echo "OhmZ $VERSION installed to $INSTALL_DIR/ohmz"
echo "Run 'ohmz --help' to get started"
