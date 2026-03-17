#!/bin/sh
set -eu
umask 022

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PKG_NAME="nmap-extended-daemon"
DIST_DIR="$ROOT_DIR/dist"
PKG_ROOT="$DIST_DIR/${PKG_NAME}_pkgroot"
DEBIAN_DIR="$PKG_ROOT/DEBIAN"

if [ ! -x "$ROOT_DIR/nmap" ]; then
    echo "Missing built daemon binary ($ROOT_DIR/nmap). Run 'make build-daemon-portable' first." >&2
    exit 2
fi

RAW_VERSION=$("$ROOT_DIR/nmap" --version | sed -n '1s/^Nmap version \([^ ]*\).*/\1/p')
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

install -m 0755 "$ROOT_DIR/nmap" "$PKG_ROOT/usr/lib/nmap_extended/nmap_extended.bin"
install -m 0755 "$ROOT_DIR/packaging/debian-daemon/nmap_extended_wrapper.sh" "$PKG_ROOT/usr/bin/nmap_extended"
install -m 0644 "$ROOT_DIR/packaging/debian-daemon/nmap-extended-daemon.service" "$PKG_ROOT/lib/systemd/system/nmap-extended-daemon.service"

for file_name in nmap-services nmap-service-probes nmap-protocols nmap-rpc nmap-mac-prefixes nmap-os-db nse_main.lua; do
    install -m 0644 "$ROOT_DIR/$file_name" "$PKG_ROOT/usr/share/nmap_extended/$file_name"
done

cp -a "$ROOT_DIR/scripts" "$PKG_ROOT/usr/share/nmap_extended/scripts"
cp -a "$ROOT_DIR/nselib" "$PKG_ROOT/usr/share/nmap_extended/nselib"
find "$PKG_ROOT/usr/share/nmap_extended/scripts" -type d -exec chmod 0755 {} +
find "$PKG_ROOT/usr/share/nmap_extended/scripts" -type f -exec chmod 0644 {} +
find "$PKG_ROOT/usr/share/nmap_extended/nselib" -type d -exec chmod 0755 {} +
find "$PKG_ROOT/usr/share/nmap_extended/nselib" -type f -exec chmod 0644 {} +

NMAPDIR="$PKG_ROOT/usr/share/nmap_extended" \
"$PKG_ROOT/usr/lib/nmap_extended/nmap_extended.bin" --service-config-generate "$PKG_ROOT/etc/nmap_extended/service_config.json" --force >/dev/null

cat > "$DEBIAN_DIR/control" <<CONTROL
Package: $PKG_NAME
Version: $DEB_VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: nmap_extended maintainer <noreply@example.invalid>
Depends: libc6, libstdc++6
Recommends: systemd
Description: Nmap Extended daemon package
 Conflict-free daemon-focused packaging for nmap_extended control-plane service mode.
CONTROL

cat > "$DEBIAN_DIR/conffiles" <<CONFFILES
/etc/nmap_extended/service_config.json
CONFFILES

install -m 0755 "$ROOT_DIR/packaging/debian-daemon/postinst" "$DEBIAN_DIR/postinst"
install -m 0755 "$ROOT_DIR/packaging/debian-daemon/prerm" "$DEBIAN_DIR/prerm"
install -m 0755 "$ROOT_DIR/packaging/debian-daemon/postrm" "$DEBIAN_DIR/postrm"

fakeroot dpkg-deb --build "$PKG_ROOT" "$OUT_DEB" >/dev/null

echo "Built package: $OUT_DEB"
