#!/usr/bin/env bash
set -euo pipefail

TOOL="${1:-}"
if [[ "${TOOL}" != "memcheck" && "${TOOL}" != "helgrind" ]]; then
    echo "Usage: $0 <memcheck|helgrind>" >&2
    exit 2
fi

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
TS_DIR="${ROOT_DIR}/nmap_extended_ts_client"

LOG_DIR="${VALGRIND_LOG_DIR:-${ROOT_DIR}/dist/valgrind/${TOOL}}"
SUPPRESSIONS_FILE="${VALGRIND_SUPPRESSIONS:-${ROOT_DIR}/packaging/valgrind/nmap_extended.supp}"
SMOKE_TARGETS="${VALGRIND_SMOKE_TARGETS:-192.168.11.7,192.168.11.1,192.168.11.255}"

mkdir -p "${LOG_DIR}"
DAEMON_STDOUT_LOG="${LOG_DIR}/daemon.stdout.log"
DAEMON_STDERR_LOG="${LOG_DIR}/daemon.stderr.log"
VALGRIND_LOG="${LOG_DIR}/valgrind.${TOOL}.log"
CLIENT_LOG="${LOG_DIR}/client.integration.log"
SCAN_STDOUT_LOG="${LOG_DIR}/scan.stdout.log"
SCAN_STDERR_LOG="${LOG_DIR}/scan.stderr.log"
SCAN_VALGRIND_LOG="${LOG_DIR}/scan.valgrind.memcheck.log"
SUMMARY_LOG="${LOG_DIR}/summary.${TOOL}.txt"
SERVICE_CONFIG_PATH="${LOG_DIR}/service_config.json"

DAEMON_PID=""
cleanup() {
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill -TERM "${DAEMON_PID}" >/dev/null 2>&1 || true
        wait "${DAEMON_PID}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

for cmd in valgrind node npm timeout; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Missing required command: ${cmd}" >&2
        exit 2
    fi
done

if [[ ! -x "${ROOT_DIR}/nmap" ]]; then
    echo "Missing built daemon binary (${ROOT_DIR}/nmap)." >&2
    echo "Run 'make build-daemon-portable' first." >&2
    exit 2
fi

if [[ ! -d "${TS_DIR}/node_modules" ]]; then
    echo "TypeScript dependencies not installed in ${TS_DIR}." >&2
    echo "Run 'cd ${TS_DIR} && npm install' first." >&2
    exit 2
fi

if [[ ! -f "${SUPPRESSIONS_FILE}" ]]; then
    echo "Missing valgrind suppressions file: ${SUPPRESSIONS_FILE}" >&2
    exit 2
fi

: > "${DAEMON_STDOUT_LOG}"
: > "${DAEMON_STDERR_LOG}"
: > "${VALGRIND_LOG}"
: > "${CLIENT_LOG}"
: > "${SCAN_STDOUT_LOG}"
: > "${SCAN_STDERR_LOG}"
: > "${SCAN_VALGRIND_LOG}"
: > "${SUMMARY_LOG}"

NMAPDIR="${ROOT_DIR}" "${ROOT_DIR}/nmap" --service-config-generate "${SERVICE_CONFIG_PATH}" --force >/dev/null

VALGRIND_ARGS=(
    "--tool=${TOOL}"
    "--num-callers=30"
    "--error-exitcode=97"
    "--suppressions=${SUPPRESSIONS_FILE}"
    "--gen-suppressions=all"
    "--log-file=${VALGRIND_LOG}"
)

if [[ "${TOOL}" == "memcheck" ]]; then
    VALGRIND_ARGS+=(
        "--leak-check=full"
        "--show-leak-kinds=definite"
        "--errors-for-leak-kinds=definite"
        "--track-origins=yes"
    )
fi

NMAPDIR="${ROOT_DIR}" valgrind "${VALGRIND_ARGS[@]}" \
    "${ROOT_DIR}/nmap" --service --service-config "${SERVICE_CONFIG_PATH}" \
    >"${DAEMON_STDOUT_LOG}" 2>"${DAEMON_STDERR_LOG}" &
DAEMON_PID=$!

SERVICE_READY=0
for _ in $(seq 1 100); do
    if grep -q "Service mode listening" "${DAEMON_STDOUT_LOG}"; then
        SERVICE_READY=1
        break
    fi

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [[ "${SERVICE_READY}" -ne 1 ]]; then
    echo "Daemon did not become ready under valgrind (${TOOL})." >&2
    tail -n 80 "${DAEMON_STDOUT_LOG}" >&2 || true
    tail -n 80 "${DAEMON_STDERR_LOG}" >&2 || true
    exit 1
fi

CLIENT_EXIT=0
(
    cd "${TS_DIR}"
    NMAP_CP_URL="ws://127.0.0.1:8765/" \
    NMAP_CP_TOKEN="change_me" \
    NMAP_SCAN_TARGET="${SMOKE_TARGETS}" \
    npm run build

    NMAP_CP_URL="ws://127.0.0.1:8765/" \
    NMAP_CP_TOKEN="change_me" \
    NMAP_SCAN_TARGET="${SMOKE_TARGETS}" \
    node --test dist/tests/live_event_stream.test.js dist/tests/concurrency_cancel_diagnostics.test.js
) >"${CLIENT_LOG}" 2>&1 || CLIENT_EXIT=$?

kill -TERM "${DAEMON_PID}" >/dev/null 2>&1 || true
DAEMON_EXIT=0
wait "${DAEMON_PID}" || DAEMON_EXIT=$?
DAEMON_PID=""

ERROR_SUMMARY_LINE="$(grep -E "ERROR SUMMARY:" "${VALGRIND_LOG}" | tail -n 1 || true)"
DEFINITE_LOST_LINE="$(grep -E "definitely lost:" "${VALGRIND_LOG}" | tail -n 1 || true)"
SUPPRESSED_LINE="$(grep -E "suppressed:" "${VALGRIND_LOG}" | tail -n 1 || true)"
ERROR_COUNT="$(printf '%s' "${ERROR_SUMMARY_LINE}" | sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p')"
if [[ -z "${ERROR_COUNT}" ]]; then
    ERROR_COUNT=0
fi

SCAN_EXIT=0
SCAN_ERROR_SUMMARY_LINE="n/a"
SCAN_DEFINITE_LOST_LINE="n/a"
SCAN_ERROR_COUNT=0
if [[ "${TOOL}" == "memcheck" ]]; then
    SCAN_VALGRIND_ARGS=(
        "--tool=memcheck"
        "--num-callers=30"
        "--error-exitcode=97"
        "--suppressions=${SUPPRESSIONS_FILE}"
        "--gen-suppressions=all"
        "--leak-check=full"
        "--show-leak-kinds=definite"
        "--errors-for-leak-kinds=definite"
        "--track-origins=yes"
        "--log-file=${SCAN_VALGRIND_LOG}"
    )

    NMAPDIR="${ROOT_DIR}" valgrind "${SCAN_VALGRIND_ARGS[@]}" \
        "${ROOT_DIR}/nmap" -n -Pn -sT -p 22 "${SMOKE_TARGETS}" \
        >"${SCAN_STDOUT_LOG}" 2>"${SCAN_STDERR_LOG}" || SCAN_EXIT=$?

    SCAN_ERROR_SUMMARY_LINE="$(grep -E "ERROR SUMMARY:" "${SCAN_VALGRIND_LOG}" | tail -n 1 || true)"
    SCAN_DEFINITE_LOST_LINE="$(grep -E "definitely lost:" "${SCAN_VALGRIND_LOG}" | tail -n 1 || true)"
    SCAN_ERROR_COUNT="$(printf '%s' "${SCAN_ERROR_SUMMARY_LINE}" | sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p')"
    if [[ -z "${SCAN_ERROR_COUNT}" ]]; then
        SCAN_ERROR_COUNT=0
    fi
fi

{
    echo "tool=${TOOL}"
    echo "scan_targets=${SMOKE_TARGETS}"
    echo "client_exit=${CLIENT_EXIT}"
    echo "daemon_exit=${DAEMON_EXIT}"
    echo "scan_exit=${SCAN_EXIT}"
    echo "error_count=${ERROR_COUNT}"
    echo "error_summary=${ERROR_SUMMARY_LINE:-unavailable}"
    echo "definitely_lost=${DEFINITE_LOST_LINE:-n/a}"
    echo "scan_error_count=${SCAN_ERROR_COUNT}"
    echo "scan_error_summary=${SCAN_ERROR_SUMMARY_LINE:-n/a}"
    echo "scan_definitely_lost=${SCAN_DEFINITE_LOST_LINE:-n/a}"
    echo "suppressed=${SUPPRESSED_LINE:-n/a}"
    echo "valgrind_log=${VALGRIND_LOG}"
    echo "scan_valgrind_log=${SCAN_VALGRIND_LOG}"
    echo "client_log=${CLIENT_LOG}"
} > "${SUMMARY_LOG}"

cat "${SUMMARY_LOG}"

if [[ "${CLIENT_EXIT}" -ne 0 ]]; then
    echo "Client integration scenarios failed under valgrind (${TOOL})." >&2
    tail -n 120 "${CLIENT_LOG}" >&2 || true
    exit "${CLIENT_EXIT}"
fi

if [[ "${DAEMON_EXIT}" -ne 0 && "${DAEMON_EXIT}" -ne 143 && "${DAEMON_EXIT}" -ne 130 ]]; then
    echo "Daemon/valgrind exit was non-zero (${DAEMON_EXIT}) for ${TOOL}." >&2
    tail -n 120 "${VALGRIND_LOG}" >&2 || true
    exit "${DAEMON_EXIT}"
fi

if [[ "${ERROR_COUNT}" -ne 0 ]]; then
    echo "Valgrind reported unsuppressed errors (${ERROR_COUNT}) for ${TOOL}." >&2
    tail -n 120 "${VALGRIND_LOG}" >&2 || true
    exit 96
fi

if [[ "${TOOL}" == "memcheck" ]]; then
    if ! grep -Eq "definitely lost:[[:space:]]+0 bytes" "${VALGRIND_LOG}"; then
        echo "Memcheck reported non-zero definitely lost bytes." >&2
        tail -n 120 "${VALGRIND_LOG}" >&2 || true
        exit 98
    fi

    if [[ "${SCAN_EXIT}" -ne 0 ]]; then
        echo "Memcheck scan-path scenario failed (${SCAN_EXIT})." >&2
        tail -n 120 "${SCAN_VALGRIND_LOG}" >&2 || true
        exit "${SCAN_EXIT}"
    fi

    if [[ "${SCAN_ERROR_COUNT}" -ne 0 ]]; then
      echo "Scan-path memcheck reported unsuppressed errors (${SCAN_ERROR_COUNT})." >&2
      tail -n 120 "${SCAN_VALGRIND_LOG}" >&2 || true
      exit 95
    fi

    if ! grep -Eq "definitely lost:[[:space:]]+0 bytes" "${SCAN_VALGRIND_LOG}"; then
        echo "Scan-path memcheck reported non-zero definitely lost bytes." >&2
        tail -n 120 "${SCAN_VALGRIND_LOG}" >&2 || true
        exit 99
    fi
fi

exit 0
