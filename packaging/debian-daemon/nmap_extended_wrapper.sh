#!/bin/sh
set -eu

export NMAPDIR=/usr/share/nmap_extended
exec /usr/lib/nmap_extended/nmap_extended.bin "$@"
