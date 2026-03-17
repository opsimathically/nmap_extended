#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist/portable-musl"
CONTAINER_WORK_DIR="${DIST_DIR}/container-work"
CONTAINER_BUILD_BIN="${CONTAINER_WORK_DIR}/nmap"
BUNDLE_NAME="nmap_extended-musl-x86_64"
BUNDLE_ROOT="${DIST_DIR}/${BUNDLE_NAME}"
TARBALL_PATH="${DIST_DIR}/${BUNDLE_NAME}.tar.gz"
IMAGE="${PORTABLE_MUSL_IMAGE:-alpine:3.20}"
ENGINE="${CONTAINER_ENGINE:-}"

if [[ -z "${ENGINE}" ]]; then
    if command -v docker >/dev/null 2>&1; then
        ENGINE="docker"
    elif command -v podman >/dev/null 2>&1; then
        ENGINE="podman"
    else
        echo "Missing container engine: install Docker or Podman." >&2
        exit 2
    fi
fi

for cmd in "${ENGINE}" tar find install; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Missing required command: ${cmd}" >&2
        exit 2
    fi
done

mkdir -p "${DIST_DIR}"
rm -rf "${CONTAINER_WORK_DIR}"
mkdir -p "${CONTAINER_WORK_DIR}"

echo "Using container engine: ${ENGINE}"
echo "Using build image: ${IMAGE}"

"${ENGINE}" run --rm \
    -v "${ROOT_DIR}:/source:ro" \
    -v "${CONTAINER_WORK_DIR}:/work" \
    -w /work \
    "${IMAGE}" \
    /bin/sh -lc '
set -eu
apk add --no-cache \
    bash \
    build-base \
    linux-headers \
    autoconf \
    automake \
    libtool \
    pkgconf \
    dpkg \
    fakeroot \
    coreutils \
    grep \
    sed \
    tar \
    gzip \
    perl \
    python3 \
    boost-dev \
    boost-static \
    libpcap-dev \
    openssl-dev \
    openssl-libs-static \
    pcre2-dev \
    libssh2-dev \
    libssh2-static \
    zlib-dev \
    zlib-static
tar -C /source \
    --exclude=.git \
    --exclude=dist \
    --exclude=nmap_extended_ts_client/node_modules \
    -cf - . | tar -C /work -xf -
if [ -f Makefile ]; then
    make distclean || true
fi
./configure
make clean
make build-daemon-portable \
    STATIC=-static \
    PORTABLE_CONTROL_PLANE_LIBS="-lboost_json -lpthread"
'

if [[ ! -x "${CONTAINER_BUILD_BIN}" ]]; then
    echo "Build failed: ${CONTAINER_BUILD_BIN} was not generated." >&2
    exit 1
fi

ldd_output="$(ldd "${CONTAINER_BUILD_BIN}" 2>&1 || true)"
if printf '%s' "${ldd_output}" | grep -q "not a dynamic executable"; then
    :
else
    echo "Expected a fully static binary, but ldd indicates dynamic linkage." >&2
    printf '%s\n' "${ldd_output}" >&2
    exit 1
fi

rm -rf "${BUNDLE_ROOT}"
mkdir -p "${BUNDLE_ROOT}/bin" \
         "${BUNDLE_ROOT}/lib" \
         "${BUNDLE_ROOT}/share/nmap_extended" \
         "${BUNDLE_ROOT}/etc/nmap_extended"

install -m 0755 "${CONTAINER_BUILD_BIN}" "${BUNDLE_ROOT}/lib/nmap_extended.bin"

cat > "${BUNDLE_ROOT}/bin/nmap_extended" <<'EOF'
#!/usr/bin/env sh
set -eu
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "${SELF_DIR}/.." && pwd)
export NMAPDIR="${ROOT_DIR}/share/nmap_extended"
exec "${ROOT_DIR}/lib/nmap_extended.bin" "$@"
EOF
chmod 0755 "${BUNDLE_ROOT}/bin/nmap_extended"

for file_name in nmap-services nmap-service-probes nmap-protocols nmap-rpc nmap-mac-prefixes nmap-os-db nse_main.lua; do
    install -m 0644 "${ROOT_DIR}/${file_name}" "${BUNDLE_ROOT}/share/nmap_extended/${file_name}"
done
cp -a "${ROOT_DIR}/scripts" "${BUNDLE_ROOT}/share/nmap_extended/scripts"
cp -a "${ROOT_DIR}/nselib" "${BUNDLE_ROOT}/share/nmap_extended/nselib"
find "${BUNDLE_ROOT}/share/nmap_extended/scripts" -type d -exec chmod 0755 {} +
find "${BUNDLE_ROOT}/share/nmap_extended/scripts" -type f -exec chmod 0644 {} +
find "${BUNDLE_ROOT}/share/nmap_extended/nselib" -type d -exec chmod 0755 {} +
find "${BUNDLE_ROOT}/share/nmap_extended/nselib" -type f -exec chmod 0644 {} +

NMAPDIR="${BUNDLE_ROOT}/share/nmap_extended" \
"${BUNDLE_ROOT}/lib/nmap_extended.bin" --service-config-generate "${BUNDLE_ROOT}/etc/nmap_extended/service_config.json" --force >/dev/null

rm -f "${TARBALL_PATH}"
tar -C "${DIST_DIR}" -czf "${TARBALL_PATH}" "${BUNDLE_NAME}"

echo "Built fully static musl bundle:"
echo "  ${TARBALL_PATH}"
echo "Run with:"
echo "  ${BUNDLE_ROOT}/bin/nmap_extended --help"
