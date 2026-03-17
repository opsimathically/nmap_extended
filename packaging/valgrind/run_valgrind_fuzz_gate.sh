#!/usr/bin/env bash
set -euo pipefail

TOOL="${1:-}"
PROFILE="${2:-pr}"

if [[ "${TOOL}" != "memcheck" && "${TOOL}" != "helgrind" ]]; then
    echo "Usage: $0 <memcheck|helgrind> [pr|nightly]" >&2
    exit 2
fi

if [[ "${PROFILE}" != "pr" && "${PROFILE}" != "nightly" ]]; then
    echo "Profile must be one of: pr, nightly" >&2
    exit 2
fi

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
TS_DIR="${ROOT_DIR}/nmap_extended_ts_client"
SUPPRESSIONS_FILE="${VALGRIND_SUPPRESSIONS:-${ROOT_DIR}/packaging/valgrind/nmap_extended.supp}"
LOG_DIR="${VALGRIND_LOG_DIR:-${ROOT_DIR}/dist/valgrind/fuzz/${PROFILE}/${TOOL}}"
SCAN_TARGET="${VALGRIND_FUZZ_SCAN_TARGET:-192.168.11.1/24}"
ITERATIONS="${VALGRIND_FUZZ_ITERATIONS:-}"
TIME_BUDGET_MS="${VALGRIND_FUZZ_TIME_BUDGET_MS:-}"
SEED_BASE="${VALGRIND_FUZZ_SEED_BASE:-73331}"
REQ_TIMEOUT_MS="${VALGRIND_FUZZ_REQUEST_TIMEOUT_MS:-3000}"
HEARTBEAT_INTERVAL="${VALGRIND_FUZZ_HEARTBEAT_INTERVAL:-8}"

if [[ "${PROFILE}" == "nightly" ]]; then
    ITERATIONS="${ITERATIONS:-1500}"
    TIME_BUDGET_MS="${TIME_BUDGET_MS:-300000}"
else
    ITERATIONS="${ITERATIONS:-280}"
    TIME_BUDGET_MS="${TIME_BUDGET_MS:-55000}"
fi

if [[ "${LOG_DIR}" != /* ]]; then
    LOG_DIR="${ROOT_DIR}/${LOG_DIR#./}"
fi

mkdir -p "${LOG_DIR}"
SUMMARY_LOG="${LOG_DIR}/summary.txt"
: > "${SUMMARY_LOG}"

for cmd in valgrind node npm timeout openssl awk sed grep; do
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

(
    cd "${TS_DIR}"
    npm run build
) > "${LOG_DIR}/build.log" 2>&1

TLS_DIR="${LOG_DIR}/tls"
mkdir -p "${TLS_DIR}"
CA_KEY="${TLS_DIR}/ca.key"
CA_CERT="${TLS_DIR}/ca.crt"
SERVER_KEY="${TLS_DIR}/server.key"
SERVER_CSR="${TLS_DIR}/server.csr"
SERVER_CERT="${TLS_DIR}/server.crt"
CLIENT_KEY="${TLS_DIR}/client.key"
CLIENT_CSR="${TLS_DIR}/client.csr"
CLIENT_CERT="${TLS_DIR}/client.crt"
SERVER_EXT="${TLS_DIR}/server.ext"

openssl genrsa -out "${CA_KEY}" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 2 -out "${CA_CERT}" -subj "/CN=nmap_extended_fuzz_ca" >/dev/null 2>&1

cat > "${SERVER_EXT}" <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF

openssl genrsa -out "${SERVER_KEY}" 2048 >/dev/null 2>&1
openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial -out "${SERVER_CERT}" -days 2 -sha256 -extfile "${SERVER_EXT}" >/dev/null 2>&1

openssl genrsa -out "${CLIENT_KEY}" 2048 >/dev/null 2>&1
openssl req -new -key "${CLIENT_KEY}" -out "${CLIENT_CSR}" -subj "/CN=nmap_extended_fuzz_client" >/dev/null 2>&1
openssl x509 -req -in "${CLIENT_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial -out "${CLIENT_CERT}" -days 2 -sha256 >/dev/null 2>&1

DAEMON_PID=""
cleanup() {
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill -TERM "${DAEMON_PID}" >/dev/null 2>&1 || true
        wait "${DAEMON_PID}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

RunSingleProfile() {
    local transport_profile="$1"
    local profile_index="$2"
    local port=$((8765 + profile_index))
    local profile_dir="${LOG_DIR}/${transport_profile}"
    local config_path="${profile_dir}/service_config.json"
    local daemon_stdout="${profile_dir}/daemon.stdout.log"
    local daemon_stderr="${profile_dir}/daemon.stderr.log"
    local valgrind_log="${profile_dir}/daemon.valgrind.log"
    local fuzz_log="${profile_dir}/fuzzer.log"
    local fuzz_artifacts="${profile_dir}/fuzzer-artifacts"
    local base_url="ws://127.0.0.1:${port}/"
    local require_mtls="false"
    local include_tls="false"
    local seed=$((SEED_BASE + profile_index * 101))
    local run_timeout_sec=$((TIME_BUDGET_MS / 1000 + 70))

    mkdir -p "${profile_dir}" "${fuzz_artifacts}"
    : > "${daemon_stdout}"
    : > "${daemon_stderr}"
    : > "${valgrind_log}"
    : > "${fuzz_log}"

    if [[ "${transport_profile}" == "wss" || "${transport_profile}" == "mtls" ]]; then
        include_tls="true"
        base_url="wss://localhost:${port}/"
    fi
    if [[ "${transport_profile}" == "mtls" ]]; then
        require_mtls="true"
    fi

    if [[ "${include_tls}" == "true" ]]; then
        cat > "${config_path}" <<EOF
{
  "runtime": {
    "bind_addr": "127.0.0.1",
    "port": ${port},
    "max_event_buffer": 8192,
    "max_active_scans": 4,
    "cancel_grace_ms": 5000
  },
  "auth": {
    "provider": "inline_token",
    "token": "change_me"
  },
  "tls": {
    "enabled": true,
    "cert_file": "${SERVER_CERT}",
    "key_file": "${SERVER_KEY}",
    "ca_file": "${CA_CERT}",
    "require_client_cert": ${require_mtls},
    "allow_insecure_remote_ws": false,
    "min_tls_version": "tls1_2"
  }
}
EOF
    else
        cat > "${config_path}" <<EOF
{
  "runtime": {
    "bind_addr": "127.0.0.1",
    "port": ${port},
    "max_event_buffer": 8192,
    "max_active_scans": 4,
    "cancel_grace_ms": 5000
  },
  "auth": {
    "provider": "inline_token",
    "token": "change_me"
  },
  "tls": {
    "enabled": false,
    "cert_file": "${SERVER_CERT}",
    "key_file": "${SERVER_KEY}",
    "ca_file": "${CA_CERT}",
    "require_client_cert": false,
    "allow_insecure_remote_ws": false,
    "min_tls_version": "tls1_2"
  }
}
EOF
    fi

    local -a valgrind_args=(
        "--tool=${TOOL}"
        "--num-callers=30"
        "--error-exitcode=97"
        "--suppressions=${SUPPRESSIONS_FILE}"
        "--gen-suppressions=all"
        "--log-file=${valgrind_log}"
    )

    if [[ "${TOOL}" == "memcheck" ]]; then
        valgrind_args+=(
            "--leak-check=full"
            "--show-leak-kinds=definite"
            "--errors-for-leak-kinds=definite"
            "--track-origins=yes"
        )
    fi

    NMAPDIR="${ROOT_DIR}" valgrind "${valgrind_args[@]}" \
        "${ROOT_DIR}/nmap" --service --service-config "${config_path}" \
        >"${daemon_stdout}" 2>"${daemon_stderr}" &
    DAEMON_PID=$!

    local service_ready=0
    for _ in $(seq 1 200); do
        if grep -q "Service mode listening" "${daemon_stdout}"; then
            service_ready=1
            break
        fi
        if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done

    if [[ "${service_ready}" -ne 1 ]]; then
        echo "daemon_start_failed profile=${transport_profile}" >> "${SUMMARY_LOG}"
        tail -n 120 "${daemon_stdout}" >&2 || true
        tail -n 120 "${daemon_stderr}" >&2 || true
        return 1
    fi

    local -a fuzz_cmd=(
        node
        dist-tests/tests/websocket_api_fuzz_runner.js
        --base-url "${base_url}"
        --auth-token "change_me"
        --scan-target "${SCAN_TARGET}"
        --transport-profile "${transport_profile}"
        --iterations "${ITERATIONS}"
        --time-budget-ms "${TIME_BUDGET_MS}"
        --seed "${seed}"
        --artifact-dir "${fuzz_artifacts}"
        --heartbeat-interval "${HEARTBEAT_INTERVAL}"
        --request-timeout-ms "${REQ_TIMEOUT_MS}"
        --reject-unauthorized-tls "true"
    )

    if [[ "${include_tls}" == "true" ]]; then
        fuzz_cmd+=(
            --ca-file "${CA_CERT}"
            --server-name "localhost"
        )
    fi
    if [[ "${require_mtls}" == "true" ]]; then
        fuzz_cmd+=(
            --client-cert-file "${CLIENT_CERT}"
            --client-key-file "${CLIENT_KEY}"
            --require-mtls "true"
        )
    fi

    local fuzz_exit=0
    (
        cd "${TS_DIR}"
        timeout "${run_timeout_sec}s" "${fuzz_cmd[@]}"
    ) > "${fuzz_log}" 2>&1 || fuzz_exit=$?

    kill -TERM "${DAEMON_PID}" >/dev/null 2>&1 || true
    local daemon_exit=0
    wait "${DAEMON_PID}" || daemon_exit=$?
    DAEMON_PID=""

    local error_summary_line
    error_summary_line="$(grep -E "ERROR SUMMARY:" "${valgrind_log}" | tail -n 1 || true)"
    local error_count
    error_count="$(printf '%s' "${error_summary_line}" | sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p')"
    error_count="${error_count:-0}"
    local definitely_lost_line="n/a"
    if [[ "${TOOL}" == "memcheck" ]]; then
        definitely_lost_line="$(grep -E "definitely lost:" "${valgrind_log}" | tail -n 1 || true)"
    fi

    {
        echo "profile=${transport_profile}"
        echo "tool=${TOOL}"
        echo "campaign_profile=${PROFILE}"
        echo "seed=${seed}"
        echo "iterations=${ITERATIONS}"
        echo "time_budget_ms=${TIME_BUDGET_MS}"
        echo "fuzz_exit=${fuzz_exit}"
        echo "daemon_exit=${daemon_exit}"
        echo "error_count=${error_count}"
        echo "error_summary=${error_summary_line:-unavailable}"
        echo "definitely_lost=${definitely_lost_line}"
        echo "fuzzer_log=${fuzz_log}"
        echo "valgrind_log=${valgrind_log}"
        echo "fuzzer_artifacts=${fuzz_artifacts}"
        echo "---"
    } >> "${SUMMARY_LOG}"

    if [[ "${fuzz_exit}" -ne 0 ]]; then
        echo "Fuzzer failed for transport profile ${transport_profile} (exit=${fuzz_exit})." >&2
        tail -n 160 "${fuzz_log}" >&2 || true
        return "${fuzz_exit}"
    fi

    if [[ "${daemon_exit}" -ne 0 && "${daemon_exit}" -ne 143 && "${daemon_exit}" -ne 130 ]]; then
        echo "Daemon/valgrind exited unexpectedly for profile ${transport_profile} (exit=${daemon_exit})." >&2
        tail -n 160 "${valgrind_log}" >&2 || true
        return "${daemon_exit}"
    fi

    if [[ "${error_count}" -ne 0 ]]; then
        echo "Valgrind reported unsuppressed errors for profile ${transport_profile}: ${error_count}" >&2
        tail -n 160 "${valgrind_log}" >&2 || true
        return 96
    fi

    if [[ "${TOOL}" == "memcheck" ]]; then
        if ! grep -Eq "definitely lost:[[:space:]]+0 bytes" "${valgrind_log}"; then
            echo "Memcheck reported non-zero definitely lost bytes for profile ${transport_profile}." >&2
            tail -n 160 "${valgrind_log}" >&2 || true
            return 98
        fi
    fi

    if [[ ! -f "${fuzz_artifacts}/summary.json" ]]; then
        echo "Missing fuzz summary artifact for profile ${transport_profile}." >&2
        return 92
    fi

    if ! grep -q '"success":[[:space:]]*true' "${fuzz_artifacts}/summary.json"; then
        echo "Fuzz summary indicates failure for profile ${transport_profile}." >&2
        cat "${fuzz_artifacts}/summary.json" >&2 || true
        return 93
    fi

    return 0
}

RunSingleProfile "ws" 1
RunSingleProfile "wss" 2
RunSingleProfile "mtls" 3

cat "${SUMMARY_LOG}"
exit 0
