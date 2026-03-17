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
  - `wss://` expected by default.
  - `ws://` only allowed via explicit `allow_insecure_ws: true` override.

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
        base_url: 'ws://127.0.0.1:8765/',
        auth_token: 'your_token_here',
        allow_insecure_ws: true
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

Changesets release flow:

```bash
npm run changeset
npm run version-packages
npm run release
```

## Daemon Config Template

Generate a baseline daemon config:

```bash
./nmap_extended --service-config-generate ./service_config.json
```

Overwrite an existing config intentionally:

```bash
./nmap_extended --service-config-generate ./service_config.json --force
```

## Disclaimer

This code is primarily for the maintainer's personal purposes.
Stability is not guaranteed.
If you use this code, you do so at your own risk.
