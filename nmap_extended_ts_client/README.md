# @opsimathically/nmap-extended-sdk

TypeScript SDK and debug CLI for the `nmap_extended` websocket control plane.

## Features

- Typed request/response/event protocol models.
- Command API for:
  - `ping`
  - `get_capabilities`
  - `start_scan`
  - `get_job`
  - `list_jobs`
  - `cancel_job`
  - `subscribe_events`
  - `get_daemon_diagnostics`
  - `get_job_diagnostics`
- Event streaming with per-job replay cursor tracking (`last_event_id`).
- Reconnect support with bounded backoff and jitter.
- Security defaults:
  - `wss://` expected by default with strict certificate verification.
  - `ws://` only allowed via explicit `allow_insecure_ws: true` override.
  - Optional TLS options: `ca_file`, `client_cert_file`, `client_key_file`, `server_name`.

## Install

From npm:

```bash
npm install @opsimathically/nmap-extended-sdk
```

From this repository (local development):

```bash
cd ./nmap_extended_ts_client
npm install
```

## Programmatic Usage

```typescript
import { NmapControlPlaneClient } from '@opsimathically/nmap-extended-sdk';

async function Main(): Promise<void> {
    const client = new NmapControlPlaneClient({
        base_url: 'wss://127.0.0.1:8765/',
        auth_token: 'your_token_here',
        websocket_tls_settings: {
            reject_unauthorized_tls: true,
            ca_file: '/etc/nmap_extended/tls/ca.crt',
            client_cert_file: '/etc/nmap_extended/tls/client.crt',
            client_key_file: '/etc/nmap_extended/tls/client.key',
            server_name: 'nmap-extended.local'
        }
    });

    client.onEvent({
        handler: ({ event_type, payload }) => {
            console.log(event_type, payload);
        }
    });

    await client.connect();
    const daemon_diagnostics = await client.getDaemonDiagnostics();
    console.log(daemon_diagnostics.scheduler_health);

    const started_job = await client.startScan({ args: ['-n', '-Pn', '-sT', '-p', '22', '192.168.11.1/24'] });
    await client.subscribeEvents({ job_id: started_job.job_id });
    client.disconnect();
}

void Main();
```

## Debug CLI (Secondary Entry Point)

Package subpath import:

```typescript
import '@opsimathically/nmap-extended-sdk/cli';
```

Executable (when installed globally or via `npx`):

```bash
nmap-extended-sdk-debug \
  --url wss://127.0.0.1:8765/ \
  --token your_token_here \
  --ca-file /etc/nmap_extended/tls/ca.crt \
  --client-cert-file /etc/nmap_extended/tls/client.crt \
  --client-key-file /etc/nmap_extended/tls/client.key \
  --server-name nmap-extended.local \
  -- -n -Pn -sT -p 22 192.168.11.1/24
```

Local-only insecure example:

```bash
nmap-extended-sdk-debug \
  --url ws://127.0.0.1:8765/ \
  --token your_token_here \
  --allow-insecure-ws \
  -- -n -Pn -sT -p 22 192.168.11.1/24
```

## Development Commands

```bash
npm run preflight:sdk
npm run build
npm run typecheck
npm run test
npm run check:api
npm run check:api:update
npm run pack:smoke
```

Stateful websocket protocol fuzzing runner (for daemon API hardening):

```bash
npm run fuzz:websocket-api -- \
  --base-url ws://127.0.0.1:8765/ \
  --auth-token change_me \
  --transport-profile ws \
  --iterations 250 \
  --time-budget-ms 45000 \
  --seed 73331 \
  --artifact-dir ./dist/fuzz/local
```

Replay a captured failure trace:

```bash
npm run fuzz:websocket-api -- \
  --base-url ws://127.0.0.1:8765/ \
  --auth-token change_me \
  --transport-profile ws \
  --replay-case ./dist/fuzz/local/failure_case.json \
  --artifact-dir ./dist/fuzz/replay
```

Changesets release flow:

```bash
npm run changeset
npm run version-packages
npm run release
```

## Daemon Config Template

Generate a baseline daemon config:

```bash
./nmap --service-config-generate ./service_config.json
```

Overwrite an existing config intentionally:

```bash
./nmap --service-config-generate ./service_config.json --force
```

## Disclaimer

This code is primarily for the maintainer's personal purposes.
Stability is not guaranteed.
If you use this code, you do so at your own risk.
