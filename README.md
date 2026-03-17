# nmap_extended

`nmap_extended` is a fork of Nmap with an added daemon runtime and websocket control plane, designed for programmatic scan orchestration and live event streaming.

This repository keeps the classic Nmap CLI engine while adding:
- daemon mode (`--service`) with config-driven runtime behavior,
- websocket command + event interface,
- concurrent scan scheduling with cancellation and timeouts,
- developer diagnostics endpoints,
- Debian packaging that installs a non-conflicting binary name (`nmap_extended`),
- a publishable TypeScript SDK (`@opsimathically/nmap-extended-sdk`).

Upstream Nmap scan capabilities and behavior remain available via the built engine. For baseline Nmap usage/man-page details, see https://nmap.org/docs.html.

## Current Implementation Snapshot

| Area | Current State |
|---|---|
| Daemon CLI | `--service`, `--service-config`, `--service-config-generate`, `--force`, internal `--service-worker` |
| Auth model | Required token in websocket URL query (`?token=...`), providers: `inline_token`, `token_file`, `env_var` |
| Job scheduling | Concurrent worker pool with FIFO queue (`runtime.max_active_scans`) |
| Cancellation | Queued jobs cancel immediately; running jobs use `SIGTERM` then `SIGKILL` after `runtime.cancel_grace_ms` |
| Live events | Streaming event envelopes with per-job monotonic `event_id` and replay via `last_event_id` |
| Backpressure | Bounded event buffer (`runtime.max_event_buffer`) with explicit `stream_backpressure` and `event_loss` events |
| Diagnostics | `get_daemon_diagnostics` and `get_job_diagnostics` over websocket |
| Transport security | Native `wss://` support with optional mTLS (`tls.require_client_cert`) |
| Portable build | `make build-daemon-portable`, `make check-daemon-portable` |
| Cross-distro portable artifact | `make build-daemon-musl-portable` -> fully static `musl` tarball |
| Debian package (glibc) | `make package-daemon-deb` / `make package-daemon-deb-gated` -> `dist/nmap-extended-daemon_<version>_<arch>.deb` |
| Debian package (musl-static core) | `make package-daemon-deb-musl` / `make package-daemon-deb-musl-gated` -> `dist/nmap-extended-daemon-musl_<version>_<arch>.deb` |
| Installed binary name | `nmap_extended` (no `/usr/bin/nmap` conflict) |
| Valgrind gate | `check-valgrind-memcheck`, `check-valgrind-helgrind`, `check-valgrind` (blocking gate) |
| Websocket fuzz gate | `check-fuzz-valgrind*` (stateful API fuzzing across `ws`/`wss`/`wss+mTLS`) |
| TypeScript SDK | Publishable package `@opsimathically/nmap-extended-sdk` (ESM+CJS+types) |

## Install and Build

### Source Build Quickstart

```bash
./configure
make
./nmap --version
```

### Portable Daemon Build and Packaging

```bash
# Toolchain/static-lib preflight
make preflight-daemon-portable

# Build portable daemon-focused binary profile
make build-daemon-portable

# Inspect dynamic footprint
make check-daemon-portable

# Build Debian package
make package-daemon-deb

# Build Debian package with mandatory valgrind gate
make package-daemon-deb-gated

# Build Debian package that stages the fully static musl daemon binary
make package-daemon-deb-musl

# Build musl-static Debian package with mandatory valgrind gate
make package-daemon-deb-musl-gated
```

### Maximum Portability Build (Cross-Distro)

For "copy and run on most x86-64 Linux distributions", use the fully static musl bundle:

```bash
make preflight-daemon-musl-portable
make build-daemon-musl-portable
```

Output artifact:
- `dist/portable-musl/nmap_extended-musl-x86_64.tar.gz`

Notes:
- this path uses a containerized Alpine/musl toolchain,
- resulting `nmap_extended.bin` is expected to be fully static (`ldd` reports not a dynamic executable),
- this is the preferred path for distro-agnostic binary portability.

### Valgrind Quality Gate

```bash
# Preflight: valgrind + node/npm + suppressions + TS deps
make preflight-valgrind

# Memcheck gate
make check-valgrind-memcheck

# Helgrind gate
make check-valgrind-helgrind

# Full blocking gate
make check-valgrind
```

### Websocket API Fuzz + Valgrind Gate

PR-bounded campaign:

```bash
make preflight-fuzz-valgrind
make check-fuzz-valgrind
```

Nightly/exhaustive campaign:

```bash
make check-fuzz-valgrind-nightly
```

Fuzz artifacts/logs are written under:
- `dist/valgrind/fuzz/pr/`
- `dist/valgrind/fuzz/nightly/`

Valgrind artifacts are written under:
- `dist/valgrind/memcheck/`
- `dist/valgrind/helgrind/`

### Dependency-Gated Workflow

For build/package/valgrind phases, the workflow is dependency-gated:
1. Run preflight target.
2. If missing tools/libs are reported, install them.
3. Re-run preflight and continue only when it passes.

### Artifact Hygiene Check (Pre-Commit / CI)

Run this before opening a PR to ensure no compiled/generated artifacts are tracked:

```bash
make check-artifact-hygiene
```

The same check is enforced in CI via the `artifact-hygiene` workflow.

## Daemon Mode

### CLI Flags

The root help output contains a **DAEMON MODE** section.

| Flag | Description |
|---|---|
| `--service` | Run daemon mode (requires `--service-config <path>`) |
| `--service-config <path>` | Load JSON runtime/auth configuration |
| `--service-config-generate <path>` | Generate a generic daemon config template |
| `--force` | Allow overwrite when generating config |
| `--service-worker` | Internal worker flag; not for direct user use |

Notes:
- `--service` and `--service-config-generate` are mutually exclusive.
- Runtime override CLI flags are rejected in service mode; config file is authoritative.

### Generate a Baseline Config

```bash
./nmap --service-config-generate ./service_config.json
```

Overwrite existing template intentionally:

```bash
./nmap --service-config-generate ./service_config.json --force
```

### Generated Config Example

```json
{
  "runtime": {
    "bind_addr": "127.0.0.1",
    "port": 8765,
    "max_event_buffer": 4096,
    "max_active_scans": 4,
    "cancel_grace_ms": 5000
  },
  "auth": {
    "provider": "inline_token",
    "token": "change_me"
  },
  "tls": {
    "enabled": false,
    "cert_file": "/etc/nmap_extended/tls/server.crt",
    "key_file": "/etc/nmap_extended/tls/server.key",
    "ca_file": "/etc/nmap_extended/tls/ca.crt",
    "require_client_cert": false,
    "allow_insecure_remote_ws": false,
    "min_tls_version": "tls1_2"
  }
}
```

### Config Field Reference

| Path | Type | Constraint / Meaning |
|---|---|---|
| `runtime.bind_addr` | string | IP bind address |
| `runtime.port` | integer | `1..65535` |
| `runtime.max_event_buffer` | integer | `64..1048576` events per job ring buffer |
| `runtime.max_active_scans` | integer | `1..256` concurrent active jobs |
| `runtime.cancel_grace_ms` | integer | `100..600000` ms TERM->KILL grace |
| `auth.provider` | string | `inline_token`, `token_file`, or `env_var` |
| `auth.token` | string | Required for `inline_token` |
| `auth.token_file` | string | Required for `token_file`, file must resolve to non-empty token |
| `auth.env_var` | string | Required for `env_var`, env var must be set and non-empty |
| `tls.enabled` | boolean | Enable native TLS transport (`wss://`) |
| `tls.cert_file` | string | Server certificate chain file; required when `tls.enabled=true` |
| `tls.key_file` | string | Server private key file; required when `tls.enabled=true` |
| `tls.ca_file` | string | Optional CA bundle; required when `tls.require_client_cert=true` |
| `tls.require_client_cert` | boolean | Enable mTLS client certificate requirement |
| `tls.allow_insecure_remote_ws` | boolean | Allow non-loopback `ws://` when `tls.enabled=false` |
| `tls.min_tls_version` | string | `tls1_2` or `tls1_3` |

### Start the Daemon

Local source-tree run:

```bash
NMAPDIR=. ./nmap --service --service-config ./service_config.json
```

Expected startup output includes:

```text
Service mode listening on ws://127.0.0.1:8765/?token=<token>
```

If you run in a restricted/containerized environment, socket operations may be blocked and startup can fail with `Error: failed to open acceptor: Operation not permitted`.

## Websocket Control Plane API

### Security and Transport

- Authentication token is required and passed via URL query parameter: `?token=<token>`.
- Native TLS is supported via config (`tls.enabled=true`) and exposes `wss://`.
- Optional mTLS is supported via `tls.require_client_cert=true`.
- When TLS is disabled, non-loopback `ws://` bind is blocked unless `tls.allow_insecure_remote_ws=true`.
- Per-session websocket `read_message_max` is set to `1 MiB`.

TLS endpoint example:

```text
wss://127.0.0.1:8765/?token=change_me
```

Local development exception (default generated config):

```text
ws://127.0.0.1:8765/?token=change_me
```

### Envelope Schemas

Request envelope:

```json
{
  "request_id": "req-123",
  "command": "start_scan",
  "payload": {
    "args": ["-n", "-Pn", "-sT", "-p", "22", "192.168.11.1/24"],
    "timeout_ms": 20000
  }
}
```

Response envelope:

```json
{
  "request_id": "req-123",
  "status": "ok",
  "payload": {
    "job_id": "job-7",
    "status": "job_queued",
    "timeout_requested": true,
    "timeout_ms": 20000
  }
}
```

Error response:

```json
{
  "request_id": "req-123",
  "status": "error",
  "payload": {},
  "error": "payload.args must be an array of strings"
}
```

Event envelope:

```json
{
  "event_id": 42,
  "job_id": "job-7",
  "event_type": "port_state_changed",
  "ts": "2026-03-17T08:00:00Z",
  "payload": {
    "host": "192.168.11.7",
    "port": 22,
    "proto": "tcp",
    "state": "open"
  }
}
```

### Commands

Supported commands:
- `ping`
- `get_capabilities`
- `start_scan`
- `get_job`
- `list_jobs`
- `cancel_job`
- `subscribe_events`
- `get_daemon_diagnostics`
- `get_job_diagnostics`

Command details:

| Command | Payload | Notes |
|---|---|---|
| `ping` | `{}` | Connectivity check, returns `{ "message": "pong" }` |
| `get_capabilities` | `{}` | Returns command list, max concurrency, and delivery mode |
| `start_scan` | `{ "args": string[], "timeout_ms"?: int }` | `args` required; validated against allowlist and limits |
| `get_job` | `{ "job_id": string }` | Basic job status and exit code |
| `list_jobs` | `{}` | Snapshot of all jobs tracked in daemon state |
| `cancel_job` | `{ "job_id": string }` | Cancel queued or running job |
| `subscribe_events` | `{ "job_id": string, "last_event_id"?: int }` | Live stream + replay from cursor |
| `get_daemon_diagnostics` | `{}` | Daemon health/runtime/counter snapshot |
| `get_job_diagnostics` | `{ "job_id": string }` | Per-job flags, counters, timing, recent warnings/errors |

### `start_scan` Argument Validation

`payload.args` is validated server-side:
- max 256 args,
- each arg length `1..512`, no newline chars,
- service-control flags are disallowed,
- unsupported options are rejected,
- only allowlisted scan options are accepted.

Optional timeout:
- `payload.timeout_ms` range: `1..604800000`.

### Event Taxonomy

Lifecycle and scheduler events:
- `job_queued`, `job_started`, `job_progress`, `job_completed`, `job_failed`, `job_canceled`, `job_timeout`

Discovery/result events:
- `host_discovered`, `host_state_changed`, `port_state_changed`, `service_discovered`, `os_match_candidate`, `os_discovered`, `traceroute_hop`, `script_result`

Warning/error and stream health:
- `scan_warning`, `scan_error`, `stream_backpressure`, `event_loss`

### Ordering, Replay, and Delivery Semantics

- `event_id` is monotonic per job.
- `subscribe_events` with `last_event_id` replays events where `event_id > last_event_id`.
- Delivery model is at-least-once with replay cursor support.
- When buffered events are dropped due to `runtime.max_event_buffer`, daemon emits explicit `stream_backpressure` and `event_loss` notifications.

### Raw API Examples (Websocket)

Using `wscat` in local development (insecure transport explicitly local-only):

```bash
wscat -c 'ws://127.0.0.1:8765/?token=change_me'
```

Send `get_capabilities`:

```json
{"request_id":"req-1","command":"get_capabilities","payload":{}}
```

Start scan:

```json
{"request_id":"req-2","command":"start_scan","payload":{"args":["-n","-Pn","-sT","-p","22","192.168.11.1/24"],"timeout_ms":20000}}
```

Subscribe from beginning:

```json
{"request_id":"req-3","command":"subscribe_events","payload":{"job_id":"job-1","last_event_id":0}}
```

Cancel job:

```json
{"request_id":"req-4","command":"cancel_job","payload":{"job_id":"job-1"}}
```

## Developer Diagnostics

### `get_daemon_diagnostics`

Response contains:
- process metadata: `pid`, `daemon_version`, `binary_path`, `started_at`, `uptime_sec`,
- scheduler and load: `scheduler_health`, `queue_depth`, `active_jobs`, `total_jobs`, `websocket_sessions`,
- runtime limits: `bind_addr`, `port`, `max_event_buffer`, `max_active_scans`, `cancel_grace_ms`, `auth_provider`, TLS limit fields,
- transport snapshot: `mode`, `tls_enabled`, `require_client_cert`, `min_tls_version`, `cert_material_loaded`, `ca_configured`, `allow_insecure_remote_ws`,
- global counters: events, warnings/errors, backpressure/event-loss, and lifecycle totals.

Example request:

```json
{"request_id":"diag-1","command":"get_daemon_diagnostics","payload":{}}
```

### `get_job_diagnostics`

Response contains:
- identity/state: `job_id`, `status`, `phase`, `worker_pid`, `exit_code`, `raw_wait_status`,
- flags: `cancel_requested`, `timeout_requested`, `timeout_triggered`, `cancel_escalated`,
- timing: created/started/ended timestamps, elapsed ms, timeout ms,
- event stream internals: `last_event_id`, `buffered_events`, `dropped_events`,
- counters: `event_counts`, warning/error/backpressure/event-loss counts,
- recent warning/error message windows.

Example request:

```json
{"request_id":"diag-2","command":"get_job_diagnostics","payload":{"job_id":"job-1"}}
```

### Recommended Debug Loop During Active Scans

1. `start_scan`
2. `subscribe_events`
3. poll `get_job_diagnostics` every few seconds
4. poll `get_daemon_diagnostics` for scheduler pressure/session counts
5. use `cancel_job` when timeout/guardrail conditions trigger

## TypeScript SDK (`@opsimathically/nmap-extended-sdk`)

The SDK is a first-class client interface for the websocket control plane.

Package:
- `@opsimathically/nmap-extended-sdk`

Entrypoints:
- root import: `@opsimathically/nmap-extended-sdk`
- secondary CLI subpath: `@opsimathically/nmap-extended-sdk/cli`
- debug bin: `nmap-extended-sdk-debug`

### Install

```bash
npm install @opsimathically/nmap-extended-sdk
```

### ESM and CJS Imports

ESM:

```typescript
import { NmapControlPlaneClient } from '@opsimathically/nmap-extended-sdk';
```

CJS:

```javascript
const { NmapControlPlaneClient } = require('@opsimathically/nmap-extended-sdk');
```

### Full Lifecycle Example (Programmatic)

```typescript
import { NmapControlPlaneClient, event_envelope_t } from '@opsimathically/nmap-extended-sdk';

async function Main(): Promise<void> {
    const client = new NmapControlPlaneClient({
        base_url: 'wss://127.0.0.1:8765/',
        auth_token: 'change_me',
        request_timeout_ms: 60000,
        websocket_tls_settings: {
            reject_unauthorized_tls: true,
            ca_file: '/etc/nmap_extended/tls/ca.crt',
            client_cert_file: '/etc/nmap_extended/tls/client.crt',
            client_key_file: '/etc/nmap_extended/tls/client.key',
            server_name: 'nmap-extended.local'
        }
    });

    const observed_events: event_envelope_t[] = [];

    client.onEvent({
        handler: (event_message: event_envelope_t) => {
            observed_events.push(event_message);
            console.log(`[event ${event_message.event_id}] ${event_message.event_type}`);
        }
    });

    await client.connect();

    const caps = await client.getCapabilities();
    console.log('capabilities', caps);

    const start = await client.startScan({
        args: ['-n', '-Pn', '-sT', '-p', '22', '192.168.11.1/24'],
        timeout_ms: 20000
    });

    const job_id = start.job_id;

    const diag_before = await client.getJobDiagnostics({ job_id });
    console.log('job_diagnostics_before', diag_before);

    await client.subscribeEvents({ job_id, last_event_id: 0 });

    const cursor = client.getLastEventId({ job_id });
    console.log('replay_cursor', cursor);

    // Replay/resume example (event_id > cursor will be streamed)
    await client.subscribeEvents({ job_id, last_event_id: cursor });

    const daemon_diag = await client.getDaemonDiagnostics();
    console.log('daemon_diagnostics', daemon_diag);

    const final_job = await client.getJob({ job_id });
    console.log('final_job', final_job);

    if (final_job.status !== 'job_completed') {
        await client.cancelJob({ job_id });
    }

    client.disconnect();
}

void Main();
```

### Debug CLI Example

```bash
nmap-extended-sdk-debug \
  --url wss://127.0.0.1:8765/ \
  --token change_me \
  --ca-file /etc/nmap_extended/tls/ca.crt \
  --client-cert-file /etc/nmap_extended/tls/client.crt \
  --client-key-file /etc/nmap_extended/tls/client.key \
  --server-name nmap-extended.local \
  -- -n -Pn -sT -p 22 192.168.11.1/24
```

Practical troubleshooting patterns:
- use `--allow-insecure-ws` only for trusted local development,
- verify auth token and URL before scan debugging,
- collect `get_daemon_diagnostics` + `get_job_diagnostics` snapshots when reporting bugs,
- capture event stream output with event IDs for replayable defect reproduction.

## Operational Deployment

### Debian Package Lifecycle

Build package (glibc profile):

```bash
make package-daemon-deb
```

Build package (musl-static daemon core):

```bash
make package-daemon-deb-musl
```

Install package:

```bash
sudo dpkg -i dist/nmap-extended-daemon_*.deb
# or
sudo dpkg -i dist/nmap-extended-daemon-musl_*.deb
```

Verify installed paths:

- binary wrapper: `/usr/bin/nmap_extended`
- daemon binary: `/usr/lib/nmap_extended/nmap_extended.bin`
- service unit: `/lib/systemd/system/nmap-extended-daemon.service`
- config: `/etc/nmap_extended/service_config.json`
- data dir: `/usr/share/nmap_extended`

Service control:

```bash
sudo systemctl daemon-reload
sudo systemctl status nmap-extended-daemon.service
sudo systemctl enable nmap-extended-daemon.service
sudo systemctl start nmap-extended-daemon.service
sudo systemctl stop nmap-extended-daemon.service
```

Remove package:

```bash
sudo apt remove nmap-extended-daemon
# or
sudo dpkg -r nmap-extended-daemon

sudo apt remove nmap-extended-daemon-musl
# or
sudo dpkg -r nmap-extended-daemon-musl
```

### Security Guidance (Dev vs Production)

Development:
- bind to localhost (`127.0.0.1`),
- use short-lived test token,
- allow `ws://` only on local trusted host.

Production/remote:
- keep daemon bind scope minimal,
- enable native TLS (`tls.enabled=true`) and prefer mTLS where practical,
- rotate auth tokens and avoid logging sensitive query strings,
- restrict network access to control-plane port.

## Validation and QA Workflows

### Functional Network Validation (TCP/22)

Canonical development network check:

```bash
NMAPDIR=. ./nmap -n -Pn -sT -p 22 192.168.11.1/24
```

Expected behavior:
- live host and port discoveries,
- open/closed/filtered states reflected per host,
- suitable as a quick control-plane integration sanity target.

### Control-Plane Integration Validation via SDK Tests

```bash
cd ./nmap_extended_ts_client
npm install
npm run build

NMAP_CP_URL=ws://127.0.0.1:8765/ \
NMAP_CP_TOKEN=change_me \
NMAP_SCAN_TARGET=192.168.11.1/24 \
npm test
```

Validation focus:
- findings stream before terminal events,
- concurrent scheduling up to `max_active_scans` with queued spillover,
- queued and running cancellation behavior,
- diagnostics correctness during active scans.

### Valgrind Gate Validation

```bash
make preflight-valgrind
make check-valgrind
```

Current valgrind smoke profile:
- targets: `192.168.11.7,192.168.11.1,192.168.11.255`
- args: `-n -Pn -sT -p 22`

Gate behavior:
- memcheck + helgrind are both required,
- unsuppressed errors fail gate,
- memcheck definite leaks must be zero,
- logs and summaries are persisted under `dist/valgrind/`.

Websocket fuzz gate behavior:
- stateful protocol fuzzing with valid/invalid command sequences,
- matrix coverage for `ws`, `wss`, and `wss + mTLS`,
- deterministic replay artifacts (`trace.json`, `failure_case.json`, `summary.json`) per transport profile,
- daemon heartbeat checks during fuzz runs to fail fast on hangs/unresponsive behavior.

## Known Limits and Roadmap Boundaries

- Auth token is currently URL-query based; treat URLs/logging with care.
- Non-loopback `ws://` requires explicit insecure override in config.
- Scan args are intentionally allowlisted for daemon safety; full CLI surface is not remotely exposed.
- Scheduler uses worker-process isolation (v1) rather than in-process concurrent scan execution.
- Event stream buffering is bounded by config; overflow is signaled via explicit events.
- TypeScript SDK public API is root-entrypoint based; deep internal imports are intentionally unsupported.
- Two package modes exist: glibc (`nmap-extended-daemon`) and musl-static core (`nmap-extended-daemon-musl`).
- `nmap-extended-daemon-musl` conflicts with `nmap-extended-daemon` by design; choose one package mode per host.

## Upstream References

- Nmap docs: https://nmap.org/docs.html
- Nmap man page: https://nmap.org/book/man.html
- Nmap install guide: https://nmap.org/book/install.html

## Disclaimer

This code is primarily for the maintainer's personal purposes.
Stability is not guaranteed.
If you use this code, you do so at your own risk.
