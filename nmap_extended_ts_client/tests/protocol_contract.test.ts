import test from 'node:test';
import assert from 'node:assert/strict';
import {
    CreateRequestEnvelope,
    IsEventEnvelope,
    IsResponseEnvelope
} from '../src/types';

test('CreateRequestEnvelope builds minimal request', () => {
    const request = CreateRequestEnvelope({
        request_id: 'req-1',
        command: 'ping'
    });

    assert.equal(request.request_id, 'req-1');
    assert.equal(request.command, 'ping');
    assert.deepEqual(request.payload, {});
});

test('IsResponseEnvelope validates response shape', () => {
    const valid_response = {
        request_id: 'req-1',
        status: 'ok',
        payload: { hello: 'world' }
    };

    const invalid_response = {
        request_id: 'req-1',
        status: 'ok'
    };

    assert.equal(IsResponseEnvelope(valid_response), true);
    assert.equal(IsResponseEnvelope(invalid_response), false);
});

test('IsEventEnvelope validates event shape', () => {
    const valid_event = {
        event_id: 42,
        job_id: 'job-42',
        event_type: 'job_progress',
        ts: '2026-01-01T00:00:00Z',
        payload: { pct: 10 }
    };

    const invalid_event = {
        event_id: '42',
        job_id: 'job-42',
        event_type: 'job_progress',
        ts: '2026-01-01T00:00:00Z',
        payload: { pct: 10 }
    };

    assert.equal(IsEventEnvelope(valid_event), true);
    assert.equal(IsEventEnvelope(invalid_event), false);
});
