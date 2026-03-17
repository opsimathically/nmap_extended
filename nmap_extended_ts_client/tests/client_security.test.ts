import test from 'node:test';
import assert from 'node:assert/strict';
import { NmapControlPlaneClient } from '../src/client';

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
