#!/usr/bin/env bash
set -euo pipefail

BIN_PATH="${1:-}"
MAX_GLIBC_VERSION="${2:-2.35}"

if [[ -z "${BIN_PATH}" ]]; then
    echo "Usage: $0 <binary_path> [max_glibc_version]" >&2
    exit 2
fi

if [[ ! -f "${BIN_PATH}" ]]; then
    echo "Binary not found: ${BIN_PATH}" >&2
    exit 2
fi

if ! command -v objdump >/dev/null 2>&1; then
    echo "Missing required tool: objdump" >&2
    exit 2
fi

required_versions="$(objdump -T "${BIN_PATH}" 2>/dev/null \
    | sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' \
    | sort -V -u)"

if [[ -z "${required_versions}" ]]; then
    echo "No dynamic GLIBC symbol requirements found in ${BIN_PATH}."
    echo "Binary may be fully static or non-glibc-linked for libc symbols."
    exit 0
fi

required_max_version="$(printf '%s\n' "${required_versions}" | tail -n 1)"
highest_of_two="$(printf '%s\n%s\n' "${MAX_GLIBC_VERSION}" "${required_max_version}" | sort -V | tail -n 1)"

echo "Detected GLIBC requirements: $(printf '%s' "${required_versions}" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
echo "Maximum required GLIBC version: ${required_max_version}"
echo "Configured maximum allowed GLIBC version: ${MAX_GLIBC_VERSION}"

if [[ "${highest_of_two}" == "${required_max_version}" && "${required_max_version}" != "${MAX_GLIBC_VERSION}" ]]; then
    echo "GLIBC compatibility check failed for ${BIN_PATH}." >&2
    echo "This binary requires GLIBC ${required_max_version}, which is newer than allowed ${MAX_GLIBC_VERSION}." >&2
    echo "Build/package on an older baseline (for Ubuntu 22.04, use glibc 2.35 builder)." >&2
    exit 1
fi

echo "GLIBC compatibility check passed."

