#!/bin/sh
set -eu
umask 022

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PKG_NAME="nmap-extended-daemon-musl"
DIST_DIR="$ROOT_DIR/dist"
PORTABLE_BUNDLE_NAME="nmap_extended-musl-x86_64"
PORTABLE_BUNDLE_ROOT="$DIST_DIR/portable-musl/$PORTABLE_BUNDLE_NAME"
PORTABLE_BIN="$PORTABLE_BUNDLE_ROOT/lib/nmap_extended.bin"
PORTABLE_CONFIG="$PORTABLE_BUNDLE_ROOT/etc/nmap_extended/service_config.json"
PKG_ROOT="$DIST_DIR/${PKG_NAME}_pkgroot"
DEBIAN_DIR="$PKG_ROOT/DEBIAN"

if [ ! -x "$PORTABLE_BIN" ]; then
    echo "Missing portable musl binary ($PORTABLE_BIN)." >&2
    echo "Run 'make build-daemon-musl-portable' first." >&2
    exit 2
fi

for cmd in dpkg-deb fakeroot ldd; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required tool: $cmd" >&2
        exit 2
    fi
done

LDD_OUTPUT=$(ldd "$PORTABLE_BIN" 2>&1 || true)
case "$LDD_OUTPUT" in
    *"not a dynamic executable"*)
        ;;
    *)
        echo "Refusing to package non-static binary for musl package mode." >&2
        printf '%s\n' "$LDD_OUTPUT" >&2
        exit 1
        ;;
esac

RAW_VERSION=$("$PORTABLE_BIN" --version | sed -n '1s/^Nmap version \([^ ]*\).*/\1/p')
DEB_VERSION=$(printf '%s' "$RAW_VERSION" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-z.+:~-]/./g')
if [ -z "$DEB_VERSION" ]; then
    DEB_VERSION="0.0.0"
fi

ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
OUT_DEB="$DIST_DIR/${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"

rm -rf "$PKG_ROOT"
mkdir -p "$DEBIAN_DIR" \
         "$PKG_ROOT/usr/bin" \
         "$PKG_ROOT/usr/lib/nmap_extended" \
         "$PKG_ROOT/usr/share/nmap_extended" \
         "$PKG_ROOT/etc/nmap_extended" \
         "$PKG_ROOT/lib/systemd/system"

install -m 0755 "$PORTABLE_BIN" "$PKG_ROOT/usr/lib/nmap_extended/nmap_extended.bin"
install -m 0755 "$ROOT_DIR/packaging/debian-daemon/nmap_extended_wrapper.sh" "$PKG_ROOT/usr/bin/nmap_extended"
install -m 0644 "$ROOT_DIR/packaging/debian-daemon/nmap-extended-daemon.service" "$PKG_ROOT/lib/systemd/system/nmap-extended-daemon.service"

cp -a "$PORTABLE_BUNDLE_ROOT/share/nmap_extended/." "$PKG_ROOT/usr/share/nmap_extended/"
find "$PKG_ROOT/usr/share/nmap_extended" -type d -exec chmod 0755 {} +
find "$PKG_ROOT/usr/share/nmap_extended" -type f -exec chmod 0644 {} +

if [ -f "$PORTABLE_CONFIG" ]; then
    install -m 0644 "$PORTABLE_CONFIG" "$PKG_ROOT/etc/nmap_extended/service_config.json"
else
    NMAPDIR="$PKG_ROOT/usr/share/nmap_extended" \
    "$PKG_ROOT/usr/lib/nmap_extended/nmap_extended.bin" --service-config-generate "$PKG_ROOT/etc/nmap_extended/service_config.json" --force >/dev/null
fi

cat > "$DEBIAN_DIR/control" <<CONTROL
Package: $PKG_NAME
Version: $DEB_VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: nmap_extended maintainer <noreply@example.invalid>
Conflicts: nmap-extended-daemon
Replaces: nmap-extended-daemon
Recommends: systemd
Description: Nmap Extended daemon package (musl static)
 Conflict-free daemon-focused packaging for nmap_extended service mode.
 Built from the fully static musl artifact for cross-distro runtime portability.
CONTROL

cat > "$DEBIAN_DIR/conffiles" <<CONFFILES
/etc/nmap_extended/service_config.json
CONFFILES

install -m 0755 "$ROOT_DIR/packaging/debian-daemon/postinst" "$DEBIAN_DIR/postinst"
install -m 0755 "$ROOT_DIR/packaging/debian-daemon/prerm" "$DEBIAN_DIR/prerm"
install -m 0755 "$ROOT_DIR/packaging/debian-daemon/postrm" "$DEBIAN_DIR/postrm"

fakeroot dpkg-deb --build "$PKG_ROOT" "$OUT_DEB" >/dev/null

echo "Built package: $OUT_DEB"
