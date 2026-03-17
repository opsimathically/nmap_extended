import test from 'node:test';
import assert from 'node:assert/strict';
import { NmapControlPlaneClient } from '../src/client';
import { event_envelope_t, websocket_tls_settings_t } from '../src/types';

function BuildTlsSettings(): websocket_tls_settings_t {
    return {
        reject_unauthorized_tls: process.env.NMAP_CP_TLS_INSECURE !== '1',
        ca_file: process.env.NMAP_CP_TLS_CA_FILE,
        client_cert_file: process.env.NMAP_CP_TLS_CLIENT_CERT_FILE,
        client_key_file: process.env.NMAP_CP_TLS_CLIENT_KEY_FILE,
        server_name: process.env.NMAP_CP_TLS_SERVER_NAME
    };
}

test('Integration: findings stream before terminal event', { timeout: 120_000 }, async (t) => {
    const base_url = process.env.NMAP_CP_URL ?? '';
    const auth_token = process.env.NMAP_CP_TOKEN ?? '';
    const scan_target = process.env.NMAP_SCAN_TARGET ?? '192.168.11.1/24';

    if (!base_url || !auth_token) {
        t.skip('Set NMAP_CP_URL and NMAP_CP_TOKEN to run integration tests');
        return;
    }

    const allow_insecure_ws = base_url.startsWith('ws://');
    const client = new NmapControlPlaneClient({
        base_url,
        auth_token,
        allow_insecure_ws,
        request_timeout_ms: 60_000,
        websocket_tls_settings: BuildTlsSettings()
    });

    const observed_events: event_envelope_t[] = [];
    client.onEvent({
        handler: (event_message: event_envelope_t) => {
            observed_events.push(event_message);
        }
    });

    await client.connect();
    await client.ping();
    const daemon_diag_before = await client.getDaemonDiagnostics();
    assert.equal(typeof daemon_diag_before.active_jobs, 'number');

    const started_job = await client.startScan({
        args: ['-n', '-Pn', '-sT', '-p', '22', scan_target],
        timeout_ms: 20_000
    });
    const job_diag_during = await client.getJobDiagnostics({ job_id: started_job.job_id });
    assert.equal(job_diag_during.job_id, started_job.job_id);
    const daemon_diag_during = await client.getDaemonDiagnostics();
    assert.ok(daemon_diag_during.active_jobs >= 0);

    await client.subscribeEvents({
        job_id: started_job.job_id,
        handler: (event_message: event_envelope_t) => {
            observed_events.push(event_message);
        }
    });

    const terminal_index = observed_events.findIndex((event_message) =>
        event_message.event_type === 'job_completed'
        || event_message.event_type === 'job_failed'
        || event_message.event_type === 'job_canceled'
        || event_message.event_type === 'job_timeout'
    );

    assert.notEqual(terminal_index, -1);

    const discovery_index = observed_events.findIndex((event_message) =>
        event_message.event_type === 'host_discovered'
        || event_message.event_type === 'host_state_changed'
        || event_message.event_type === 'port_state_changed'
        || event_message.event_type === 'service_discovered'
        || event_message.event_type === 'os_discovered'
    );

    if (discovery_index !== -1) {
        assert.ok(discovery_index < terminal_index);
    }

    client.disconnect();
});
