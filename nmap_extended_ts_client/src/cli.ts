#!/usr/bin/env node
import { NmapControlPlaneClient } from './client';
import { event_envelope_t } from './types';

type cli_options_t = {
    base_url: string;
    auth_token: string;
    scan_args: string[];
    allow_insecure_ws: boolean;
    reject_unauthorized_tls: boolean;
    ca_file?: string;
    client_cert_file?: string;
    client_key_file?: string;
    server_name?: string;
};

function ParseCliArguments(params: { argv: string[] }): cli_options_t {
    const argv = params.argv;
    let base_url = '';
    let auth_token = '';
    let allow_insecure_ws = false;
    let reject_unauthorized_tls = true;
    let ca_file: string | undefined;
    let client_cert_file: string | undefined;
    let client_key_file: string | undefined;
    let server_name: string | undefined;
    const scan_args: string[] = [];

    let i = 0;
    while (i < argv.length) {
        const arg = argv[i];
        if (arg === '--url') {
            base_url = argv[i + 1] ?? '';
            i += 2;
            continue;
        }
        if (arg === '--token') {
            auth_token = argv[i + 1] ?? '';
            i += 2;
            continue;
        }
        if (arg === '--allow-insecure-ws') {
            allow_insecure_ws = true;
            i += 1;
            continue;
        }
        if (arg === '--insecure-tls') {
            reject_unauthorized_tls = false;
            i += 1;
            continue;
        }
        if (arg === '--ca-file') {
            ca_file = argv[i + 1] ?? '';
            i += 2;
            continue;
        }
        if (arg === '--client-cert-file') {
            client_cert_file = argv[i + 1] ?? '';
            i += 2;
            continue;
        }
        if (arg === '--client-key-file') {
            client_key_file = argv[i + 1] ?? '';
            i += 2;
            continue;
        }
        if (arg === '--server-name') {
            server_name = argv[i + 1] ?? '';
            i += 2;
            continue;
        }
        if (arg === '--') {
            scan_args.push(...argv.slice(i + 1));
            break;
        }
        i += 1;
    }

    if (!base_url || !auth_token || scan_args.length === 0) {
        throw new Error(
            'Usage: npm run debug -- --url <wss://host:port/> --token <token> [--allow-insecure-ws] [--insecure-tls] [--ca-file <path>] [--client-cert-file <path> --client-key-file <path>] [--server-name <name>] -- <nmap scan args>'
        );
    }

    return {
        base_url,
        auth_token,
        scan_args,
        allow_insecure_ws,
        reject_unauthorized_tls,
        ca_file,
        client_cert_file,
        client_key_file,
        server_name
    };
}

function PrintEvent(params: { event_message: event_envelope_t }): void {
    const line = JSON.stringify(params.event_message);
    process.stdout.write(`${line}\n`);
}

async function RunCli(): Promise<void> {
    const options = ParseCliArguments({ argv: process.argv.slice(2) });

    const client = new NmapControlPlaneClient({
        base_url: options.base_url,
        auth_token: options.auth_token,
        allow_insecure_ws: options.allow_insecure_ws,
        websocket_tls_settings: {
            reject_unauthorized_tls: options.reject_unauthorized_tls,
            ca_file: options.ca_file,
            client_cert_file: options.client_cert_file,
            client_key_file: options.client_key_file,
            server_name: options.server_name
        }
    });

    client.onEvent({
        handler: (event_message: event_envelope_t) => {
            PrintEvent({ event_message });
        }
    });

    await client.connect();

    const capabilities = await client.getCapabilities();
    process.stdout.write(`capabilities=${JSON.stringify(capabilities)}\n`);
    const daemon_diagnostics = await client.getDaemonDiagnostics();
    process.stdout.write(`daemon_diagnostics=${JSON.stringify(daemon_diagnostics)}\n`);

    const started_job = await client.startScan({ args: options.scan_args });
    process.stdout.write(`job_started=${JSON.stringify(started_job)}\n`);
    const initial_job_diagnostics = await client.getJobDiagnostics({ job_id: started_job.job_id });
    process.stdout.write(`job_diagnostics_initial=${JSON.stringify(initial_job_diagnostics)}\n`);

    await client.subscribeEvents({
        job_id: started_job.job_id,
        handler: (event_message: event_envelope_t) => {
            PrintEvent({ event_message });
        }
    });

    const final_job = await client.getJob({ job_id: started_job.job_id });
    process.stdout.write(`job_final=${JSON.stringify(final_job)}\n`);
    const final_job_diagnostics = await client.getJobDiagnostics({ job_id: started_job.job_id });
    process.stdout.write(`job_diagnostics_final=${JSON.stringify(final_job_diagnostics)}\n`);

    client.disconnect();
}

void RunCli().catch((error: unknown) => {
    const error_text = error instanceof Error ? error.message : String(error);
    process.stderr.write(`debug_cli_error=${error_text}\n`);
    process.exit(1);
});
