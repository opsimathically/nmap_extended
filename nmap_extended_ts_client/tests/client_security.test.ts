import test from 'node:test';
import assert from 'node:assert/strict';
import { NmapControlPlaneClient } from '../src/client';
import { ControlPlaneClientError } from '../src/errors';

test('Client rejects insecure ws URL by default', () => {
    assert.throws(() => {
        new NmapControlPlaneClient({
            base_url: 'ws://127.0.0.1:8765/',
            auth_token: 'token'
        });
    });
});

test('Client allows insecure ws URL only with explicit override', () => {
    const client = new NmapControlPlaneClient({
        base_url: 'ws://127.0.0.1:8765/',
        auth_token: 'token',
        allow_insecure_ws: true
    });

    assert.ok(client);
    client.disconnect();
});

test('Client rejects incomplete TLS client auth material', async () => {
    const client = new NmapControlPlaneClient({
        base_url: 'wss://127.0.0.1:8765/',
        auth_token: 'token',
        websocket_tls_settings: {
            reject_unauthorized_tls: true,
            client_cert_file: '/tmp/client.crt'
        }
    });

    await assert.rejects(async () => {
        await client.connect();
    }, (error: unknown) => {
        assert.ok(error instanceof ControlPlaneClientError);
        assert.equal(error.code, 'invalid_tls_client_auth');
        return true;
    });
});
