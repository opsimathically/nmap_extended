import test from 'node:test';
import assert from 'node:assert/strict';
import { NmapControlPlaneClient } from '../src/client';
import { websocket_tls_settings_t } from '../src/types';

type integration_env_t = {
    base_url: string;
    auth_token: string;
    scan_target: string;
};

function GetIntegrationEnv(): integration_env_t {
    return {
        base_url: process.env.NMAP_CP_URL ?? '',
        auth_token: process.env.NMAP_CP_TOKEN ?? '',
        scan_target: process.env.NMAP_SCAN_TARGET ?? '192.168.11.1/24'
    };
}

function SleepMs(params: { duration_ms: number }): Promise<void> {
    return new Promise<void>((resolve) => {
        setTimeout(resolve, params.duration_ms);
    });
}

function BuildTlsSettings(): websocket_tls_settings_t {
    return {
        reject_unauthorized_tls: process.env.NMAP_CP_TLS_INSECURE !== '1',
        ca_file: process.env.NMAP_CP_TLS_CA_FILE,
        client_cert_file: process.env.NMAP_CP_TLS_CLIENT_CERT_FILE,
        client_key_file: process.env.NMAP_CP_TLS_CLIENT_KEY_FILE,
        server_name: process.env.NMAP_CP_TLS_SERVER_NAME
    };
}

test('Integration: concurrent scheduling and queued cancel diagnostics', { timeout: 180_000 }, async (t) => {
    const env = GetIntegrationEnv();
    if (!env.base_url || !env.auth_token) {
        t.skip('Set NMAP_CP_URL and NMAP_CP_TOKEN to run integration tests');
        return;
    }

    const allow_insecure_ws = env.base_url.startsWith('ws://');
    const client = new NmapControlPlaneClient({
        base_url: env.base_url,
        auth_token: env.auth_token,
        allow_insecure_ws,
        request_timeout_ms: 90_000,
        websocket_tls_settings: BuildTlsSettings()
    });

    const scan_args = ['-n', '-Pn', '-sT', '-p', '22', env.scan_target];
    const started_job_ids: string[] = [];

    await client.connect();
    await client.ping();

    const capabilities = await client.getCapabilities();
    const max_concurrent_scans = Math.max(1, capabilities.max_concurrent_scans);
    const job_count = Math.min(max_concurrent_scans + 1, 8);

    for (let i = 0; i < job_count; i += 1) {
        const started_job = await client.startScan({
            args: scan_args,
            timeout_ms: 20_000
        });
        started_job_ids.push(started_job.job_id);
    }

    // Give scheduler a short window to assign active workers and queue overflow.
    await SleepMs({ duration_ms: 250 });

    const daemon_diag = await client.getDaemonDiagnostics();
    assert.ok(daemon_diag.active_jobs <= max_concurrent_scans);
    if (job_count > max_concurrent_scans) {
        assert.ok(daemon_diag.queue_depth >= 1);
    }

    const queued_job_id = started_job_ids[started_job_ids.length - 1];
    await client.cancelJob({ job_id: queued_job_id });

    await client.subscribeEvents({
        job_id: queued_job_id
    });

    const canceled_job = await client.getJob({ job_id: queued_job_id });
    assert.equal(canceled_job.status, 'job_canceled');

    const canceled_job_diag = await client.getJobDiagnostics({ job_id: queued_job_id });
    assert.equal(canceled_job_diag.status, 'job_canceled');
    assert.equal(canceled_job_diag.flags.cancel_requested, true);

    for (const job_id of started_job_ids.slice(0, started_job_ids.length - 1)) {
        await client.cancelJob({ job_id });
    }

    client.disconnect();
});
