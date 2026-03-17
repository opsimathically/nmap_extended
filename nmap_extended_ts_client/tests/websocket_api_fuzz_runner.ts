import WebSocket from 'ws';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve as ResolvePath } from 'node:path';

type fuzz_transport_profile_t = 'ws' | 'wss' | 'mtls';
type fuzz_action_kind_t =
    | 'valid_command'
    | 'malformed_json'
    | 'unknown_command'
    | 'wrong_types'
    | 'missing_fields'
    | 'oversized_payload'
    | 'invalid_job_id'
    | 'extreme_last_event_id'
    | 'parallel_subscription_storm';

type fuzz_tls_material_t = {
    reject_unauthorized_tls: boolean;
    ca_file?: string;
    client_cert_file?: string;
    client_key_file?: string;
    server_name?: string;
};

type fuzz_settings_t = {
    base_url: string;
    auth_token: string;
    scan_target: string;
    transport_profile: fuzz_transport_profile_t;
    iterations: number;
    time_budget_ms: number;
    seed: number;
    artifact_dir: string;
    replay_case_path?: string;
    replay_seed?: number;
    heartbeat_interval: number;
    request_timeout_ms: number;
    require_mtls: boolean;
    tls_material: fuzz_tls_material_t;
};

type fuzz_trace_entry_t = {
    iteration: number;
    action_kind: fuzz_action_kind_t;
    request_text?: string;
    request_id?: string;
    wait_ms: number;
    expect_response: boolean;
    note: string;
};

type fuzz_summary_t = {
    success: boolean;
    transport_profile: fuzz_transport_profile_t;
    seed: number;
    replay_mode: boolean;
    iterations_attempted: number;
    valid_responses: number;
    error_responses: number;
    event_messages: number;
    invariant_failures: number;
    daemon_unresponsive_failures: number;
    started_jobs: number;
    runtime_ms: number;
    artifact_dir: string;
    failure_reason?: string;
};

type fuzz_state_t = {
    request_counter: number;
    known_job_ids: string[];
    known_terminal_jobs: Set<string>;
    last_event_ids: Map<string, number>;
    summary: fuzz_summary_t;
};

type websocket_run_result_t = {
    opened: boolean;
    frames: string[];
    close_code?: number;
    close_reason?: string;
    error_text?: string;
};

type response_envelope_t = {
    request_id?: string;
    status?: string;
    payload?: unknown;
    error?: string;
};

type event_envelope_t = {
    event_id?: number;
    job_id?: string;
    event_type?: string;
    payload?: unknown;
};

type replay_case_t = {
    trace: fuzz_trace_entry_t[];
};

class DeterministicRng {
    private state: number;

    constructor(params: { seed: number }) {
        this.state = params.seed >>> 0;
        if (this.state === 0) {
            this.state = 0x6d2b79f5;
        }
    }

    nextUint32(): number {
        this.state = (1664525 * this.state + 1013904223) >>> 0;
        return this.state;
    }

    nextFloat(): number {
        return this.nextUint32() / 0x100000000;
    }

    nextInt(params: { min_inclusive: number; max_inclusive: number }): number {
        const span = params.max_inclusive - params.min_inclusive + 1;
        return params.min_inclusive + Math.floor(this.nextFloat() * span);
    }

    pickOne<T>(params: { values: T[] }): T {
        const index = this.nextInt({ min_inclusive: 0, max_inclusive: params.values.length - 1 });
        return params.values[index];
    }
}

function ParseIntegerFlag(params: { key: string; value: string; min: number; max: number }): number {
    const parsed = Number.parseInt(params.value, 10);
    if (!Number.isInteger(parsed) || parsed < params.min || parsed > params.max) {
        throw new Error(`${params.key} must be an integer in range [${params.min}, ${params.max}]`);
    }
    return parsed;
}

function ParseTransportProfile(params: { value: string }): fuzz_transport_profile_t {
    if (params.value === 'ws' || params.value === 'wss' || params.value === 'mtls') {
        return params.value;
    }
    throw new Error(`Unsupported transport profile: ${params.value}`);
}

function ParseBooleanFlag(params: { key: string; value: string }): boolean {
    if (params.value === 'true' || params.value === '1') {
        return true;
    }
    if (params.value === 'false' || params.value === '0') {
        return false;
    }
    throw new Error(`${params.key} must be true/false or 1/0`);
}

function ParseCliArgs(params: { argv: string[] }): fuzz_settings_t {
    const args = params.argv;
    let base_url = '';
    let auth_token = '';
    let scan_target = '192.168.11.1/24';
    let transport_profile: fuzz_transport_profile_t = 'ws';
    let iterations = 200;
    let time_budget_ms = 45_000;
    let seed = Date.now() >>> 0;
    let artifact_dir = './dist/fuzz';
    let replay_case_path: string | undefined;
    let replay_seed: number | undefined;
    let heartbeat_interval = 8;
    let request_timeout_ms = 3_000;
    let require_mtls = false;
    let reject_unauthorized_tls = true;
    let ca_file: string | undefined;
    let client_cert_file: string | undefined;
    let client_key_file: string | undefined;
    let server_name: string | undefined;

    for (let i = 0; i < args.length; i += 1) {
        const arg = args[i];
        const value = args[i + 1];
        if (arg === '--base-url') {
            base_url = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--auth-token') {
            auth_token = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--scan-target') {
            scan_target = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--transport-profile') {
            transport_profile = ParseTransportProfile({ value: value ?? '' });
            i += 1;
            continue;
        }
        if (arg === '--iterations') {
            iterations = ParseIntegerFlag({ key: arg, value: value ?? '', min: 1, max: 250000 });
            i += 1;
            continue;
        }
        if (arg === '--time-budget-ms') {
            time_budget_ms = ParseIntegerFlag({ key: arg, value: value ?? '', min: 1000, max: 3_600_000 });
            i += 1;
            continue;
        }
        if (arg === '--seed') {
            seed = ParseIntegerFlag({ key: arg, value: value ?? '', min: 1, max: 0x7fffffff });
            i += 1;
            continue;
        }
        if (arg === '--artifact-dir') {
            artifact_dir = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--replay-case') {
            replay_case_path = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--replay-seed') {
            replay_seed = ParseIntegerFlag({ key: arg, value: value ?? '', min: 1, max: 0x7fffffff });
            i += 1;
            continue;
        }
        if (arg === '--heartbeat-interval') {
            heartbeat_interval = ParseIntegerFlag({ key: arg, value: value ?? '', min: 1, max: 10000 });
            i += 1;
            continue;
        }
        if (arg === '--request-timeout-ms') {
            request_timeout_ms = ParseIntegerFlag({ key: arg, value: value ?? '', min: 250, max: 120_000 });
            i += 1;
            continue;
        }
        if (arg === '--require-mtls') {
            require_mtls = ParseBooleanFlag({ key: arg, value: value ?? '' });
            i += 1;
            continue;
        }
        if (arg === '--reject-unauthorized-tls') {
            reject_unauthorized_tls = ParseBooleanFlag({ key: arg, value: value ?? '' });
            i += 1;
            continue;
        }
        if (arg === '--ca-file') {
            ca_file = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--client-cert-file') {
            client_cert_file = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--client-key-file') {
            client_key_file = value ?? '';
            i += 1;
            continue;
        }
        if (arg === '--server-name') {
            server_name = value ?? '';
            i += 1;
            continue;
        }

        throw new Error(
            `Unknown argument: ${arg}. Expected --base-url --auth-token --transport-profile --iterations --time-budget-ms --seed --artifact-dir --replay-case --replay-seed --heartbeat-interval --request-timeout-ms --require-mtls --reject-unauthorized-tls --ca-file --client-cert-file --client-key-file --server-name --scan-target`
        );
    }

    if (!base_url) {
        throw new Error('--base-url is required');
    }
    if (!auth_token) {
        throw new Error('--auth-token is required');
    }
    if (!artifact_dir) {
        throw new Error('--artifact-dir is required');
    }

    return {
        base_url,
        auth_token,
        scan_target,
        transport_profile,
        iterations,
        time_budget_ms,
        seed,
        artifact_dir: ResolvePath(artifact_dir),
        replay_case_path: replay_case_path ? ResolvePath(replay_case_path) : undefined,
        replay_seed,
        heartbeat_interval,
        request_timeout_ms,
        require_mtls,
        tls_material: {
            reject_unauthorized_tls,
            ca_file,
            client_cert_file,
            client_key_file,
            server_name
        }
    };
}

function BuildAuthedUrl(params: { base_url: string; token: string }): string {
    const parsed_url = new URL(params.base_url);
    parsed_url.searchParams.set('token', params.token);
    return parsed_url.toString();
}

function BuildWebsocketOptions(params: { tls_material: fuzz_tls_material_t; include_client_cert: boolean }): WebSocket.ClientOptions {
    const options: WebSocket.ClientOptions = {
        rejectUnauthorized: params.tls_material.reject_unauthorized_tls
    };

    if (params.tls_material.ca_file) {
        options.ca = readFileSync(params.tls_material.ca_file);
    }
    if (params.include_client_cert && params.tls_material.client_cert_file) {
        options.cert = readFileSync(params.tls_material.client_cert_file);
    }
    if (params.include_client_cert && params.tls_material.client_key_file) {
        options.key = readFileSync(params.tls_material.client_key_file);
    }
    if (params.tls_material.server_name) {
        (options as WebSocket.ClientOptions & { servername?: string }).servername = params.tls_material.server_name;
    }
    return options;
}

async function RunWebsocketExchange(params: {
    url: string;
    tls_material: fuzz_tls_material_t;
    include_client_cert: boolean;
    send_text?: string;
    wait_ms: number;
}): Promise<websocket_run_result_t> {
    return new Promise<websocket_run_result_t>((resolve) => {
        const frames: string[] = [];
        let opened = false;
        let finished = false;
        let error_text: string | undefined;
        let close_code: number | undefined;
        let close_reason: string | undefined;

        const Finish = (): void => {
            if (finished) {
                return;
            }
            finished = true;
            resolve({
                opened,
                frames,
                close_code,
                close_reason,
                error_text
            });
        };

        let ws_client: WebSocket;
        try {
            ws_client = new WebSocket(
                params.url,
                BuildWebsocketOptions({
                    tls_material: params.tls_material,
                    include_client_cert: params.include_client_cert
                })
            );
        } catch (error) {
            error_text = error instanceof Error ? error.message : String(error);
            Finish();
            return;
        }

        const close_timer = setTimeout(() => {
            if (ws_client.readyState === WebSocket.OPEN) {
                ws_client.close();
            } else if (ws_client.readyState === WebSocket.CONNECTING) {
                ws_client.terminate();
            }
        }, params.wait_ms);

        const hard_timeout = setTimeout(() => {
            error_text = error_text ?? 'websocket exchange timeout';
            ws_client.terminate();
        }, params.wait_ms + 1000);

        ws_client.on('open', () => {
            opened = true;
            if (params.send_text) {
                ws_client.send(params.send_text);
            }
        });

        ws_client.on('message', (data: WebSocket.RawData) => {
            const text_frame = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
            frames.push(text_frame);
        });

        ws_client.on('error', (error: Error) => {
            error_text = error.message;
        });

        ws_client.on('close', (code: number, reason: Buffer) => {
            close_code = code;
            close_reason = reason.toString('utf8');
            clearTimeout(close_timer);
            clearTimeout(hard_timeout);
            Finish();
        });
    });
}

function ParseJsonEnvelope(params: { text: string }): response_envelope_t | event_envelope_t | undefined {
    try {
        const parsed = JSON.parse(params.text) as unknown;
        if (typeof parsed === 'object' && parsed !== null) {
            return parsed as response_envelope_t | event_envelope_t;
        }
        return undefined;
    } catch {
        return undefined;
    }
}

function IsTerminalEvent(params: { event_type: string }): boolean {
    return params.event_type === 'job_completed'
        || params.event_type === 'job_failed'
        || params.event_type === 'job_canceled'
        || params.event_type === 'job_timeout';
}

function RegisterFrameEffects(params: {
    frame_text: string;
    state: fuzz_state_t;
}): void {
    const envelope = ParseJsonEnvelope({ text: params.frame_text });
    if (!envelope) {
        return;
    }

    if (Object.prototype.hasOwnProperty.call(envelope, 'status')) {
        const response = envelope as response_envelope_t;
        if (response.status === 'ok') {
            params.state.summary.valid_responses += 1;
            const payload = response.payload as { job_id?: unknown } | undefined;
            if (payload && typeof payload.job_id === 'string') {
                if (!params.state.known_job_ids.includes(payload.job_id)) {
                    params.state.known_job_ids.push(payload.job_id);
                }
                params.state.summary.started_jobs += 1;
            }
        } else if (response.status === 'error') {
            params.state.summary.error_responses += 1;
        }
        return;
    }

    if (Object.prototype.hasOwnProperty.call(envelope, 'event_type')) {
        params.state.summary.event_messages += 1;
        const event_message = envelope as event_envelope_t;
        if (typeof event_message.job_id === 'string' && typeof event_message.event_id === 'number') {
            params.state.last_event_ids.set(event_message.job_id, event_message.event_id);
            if (!params.state.known_job_ids.includes(event_message.job_id)) {
                params.state.known_job_ids.push(event_message.job_id);
            }
        }
        if (typeof event_message.event_type === 'string' && typeof event_message.job_id === 'string') {
            if (IsTerminalEvent({ event_type: event_message.event_type })) {
                params.state.known_terminal_jobs.add(event_message.job_id);
            }
        }
    }
}

function BuildRequestEnvelope(params: {
    request_id: string;
    command: string;
    payload: Record<string, unknown>;
}): string {
    return JSON.stringify({
        request_id: params.request_id,
        command: params.command,
        payload: params.payload
    });
}

function PickWeightedAction(params: { rng: DeterministicRng }): fuzz_action_kind_t {
    const threshold = params.rng.nextInt({ min_inclusive: 1, max_inclusive: 1000 });
    if (threshold <= 320) return 'valid_command';
    if (threshold <= 430) return 'malformed_json';
    if (threshold <= 530) return 'unknown_command';
    if (threshold <= 620) return 'wrong_types';
    if (threshold <= 710) return 'missing_fields';
    if (threshold <= 795) return 'oversized_payload';
    if (threshold <= 875) return 'invalid_job_id';
    if (threshold <= 950) return 'extreme_last_event_id';
    return 'parallel_subscription_storm';
}

function BuildValidCommandRequest(params: {
    state: fuzz_state_t;
    request_id: string;
    rng: DeterministicRng;
    scan_target: string;
}): { request_text: string; note: string; wait_ms: number } {
    const known_job_id = params.state.known_job_ids.length > 0
        ? params.rng.pickOne({ values: params.state.known_job_ids })
        : 'job-999999';

    const command_choices = [
        'ping',
        'get_capabilities',
        'list_jobs',
        'get_daemon_diagnostics',
        'start_scan',
        'get_job',
        'cancel_job',
        'subscribe_events',
        'get_job_diagnostics'
    ];
    const command_name = params.rng.pickOne({ values: command_choices });

    if (command_name === 'ping'
        || command_name === 'get_capabilities'
        || command_name === 'list_jobs'
        || command_name === 'get_daemon_diagnostics') {
        return {
            request_text: BuildRequestEnvelope({
                request_id: params.request_id,
                command: command_name,
                payload: {}
            }),
            note: command_name,
            wait_ms: 500
        };
    }

    if (command_name === 'start_scan') {
        return {
            request_text: BuildRequestEnvelope({
                request_id: params.request_id,
                command: command_name,
                payload: {
                    args: ['-n', '-Pn', '-sT', '-p', '22', params.scan_target],
                    timeout_ms: params.rng.nextInt({ min_inclusive: 800, max_inclusive: 4000 })
                }
            }),
            note: 'start_scan',
            wait_ms: 1200
        };
    }

    if (command_name === 'subscribe_events') {
        const last_event_id = params.state.last_event_ids.get(known_job_id) ?? 0;
        return {
            request_text: BuildRequestEnvelope({
                request_id: params.request_id,
                command: command_name,
                payload: {
                    job_id: known_job_id,
                    last_event_id
                }
            }),
            note: `subscribe_events:${known_job_id}`,
            wait_ms: 1200
        };
    }

    return {
        request_text: BuildRequestEnvelope({
            request_id: params.request_id,
            command: command_name,
            payload: {
                job_id: known_job_id
            }
        }),
        note: `${command_name}:${known_job_id}`,
        wait_ms: 700
    };
}

function BuildMutatedRequest(params: {
    action_kind: fuzz_action_kind_t;
    request_id: string;
    state: fuzz_state_t;
    rng: DeterministicRng;
}): { request_text: string; note: string; wait_ms: number; expect_response: boolean } {
    const fake_job_id = `job-invalid-${params.rng.nextInt({ min_inclusive: 1, max_inclusive: 999999 })}`;
    const known_job_id = params.state.known_job_ids.length > 0
        ? params.rng.pickOne({ values: params.state.known_job_ids })
        : fake_job_id;

    if (params.action_kind === 'malformed_json') {
        const malformed_choices = [
            '{"request_id":"bad","command":"ping","payload":',
            '{"request_id":42,"command":"start_scan","payload":{"args":["-n"]}}',
            '[1,2,3]',
            '{"request_id":"x","command":"ping","payload":{}} trailing',
            '{"request_id":"x","command":"subscribe_events","payload":{"job_id":"job-1","last_event_id":'
        ];
        return {
            request_text: params.rng.pickOne({ values: malformed_choices }),
            note: 'malformed_json',
            wait_ms: 600,
            expect_response: false
        };
    }

    if (params.action_kind === 'unknown_command') {
        return {
            request_text: BuildRequestEnvelope({
                request_id: params.request_id,
                command: `unknown_${params.rng.nextInt({ min_inclusive: 1, max_inclusive: 9999 })}`,
                payload: {}
            }),
            note: 'unknown_command',
            wait_ms: 600,
            expect_response: true
        };
    }

    if (params.action_kind === 'wrong_types') {
        return {
            request_text: JSON.stringify({
                request_id: params.request_id,
                command: 'start_scan',
                payload: {
                    args: { not: 'array' },
                    timeout_ms: 'not-an-int'
                }
            }),
            note: 'wrong_types:start_scan',
            wait_ms: 600,
            expect_response: true
        };
    }

    if (params.action_kind === 'missing_fields') {
        const partial = params.rng.pickOne({
            values: [
                { request_id: params.request_id, payload: {} },
                { command: 'ping', payload: {} },
                { request_id: params.request_id, command: 'get_job' }
            ]
        });
        return {
            request_text: JSON.stringify(partial),
            note: 'missing_fields',
            wait_ms: 600,
            expect_response: true
        };
    }

    if (params.action_kind === 'oversized_payload') {
        const huge_blob = 'x'.repeat(1_300_000);
        return {
            request_text: JSON.stringify({
                request_id: params.request_id,
                command: 'ping',
                payload: {
                    huge_blob
                }
            }),
            note: 'oversized_payload',
            wait_ms: 1200,
            expect_response: false
        };
    }

    if (params.action_kind === 'invalid_job_id') {
        return {
            request_text: BuildRequestEnvelope({
                request_id: params.request_id,
                command: params.rng.pickOne({ values: ['get_job', 'cancel_job', 'subscribe_events', 'get_job_diagnostics'] }),
                payload: {
                    job_id: fake_job_id
                }
            }),
            note: `invalid_job_id:${fake_job_id}`,
            wait_ms: 700,
            expect_response: true
        };
    }

    if (params.action_kind === 'extreme_last_event_id') {
        return {
            request_text: BuildRequestEnvelope({
                request_id: params.request_id,
                command: 'subscribe_events',
                payload: {
                    job_id: known_job_id,
                    last_event_id: Number.MAX_SAFE_INTEGER
                }
            }),
            note: `extreme_last_event_id:${known_job_id}`,
            wait_ms: 900,
            expect_response: true
        };
    }

    return {
        request_text: BuildRequestEnvelope({
            request_id: params.request_id,
            command: 'subscribe_events',
            payload: {
                job_id: known_job_id,
                last_event_id: 0
            }
        }),
        note: `parallel_subscription_storm:${known_job_id}`,
        wait_ms: 900,
        expect_response: true
    };
}

async function ExecuteParallelSubscriptionStorm(params: {
    request_text: string;
    websocket_url: string;
    settings: fuzz_settings_t;
    trace_note: string;
}): Promise<websocket_run_result_t[]> {
    const runs = [];
    for (let i = 0; i < 3; i += 1) {
        runs.push(RunWebsocketExchange({
            url: params.websocket_url,
            tls_material: params.settings.tls_material,
            include_client_cert: params.settings.transport_profile === 'mtls',
            send_text: params.request_text,
            wait_ms: 1000
        }));
    }
    const results = await Promise.all(runs);
    process.stdout.write(`fuzz_parallel_subscription_storm=${params.trace_note}\n`);
    return results;
}

function IsSuccessfulPingResponse(params: { frame: string }): boolean {
    const parsed = ParseJsonEnvelope({ text: params.frame });
    if (!parsed || !Object.prototype.hasOwnProperty.call(parsed, 'status')) {
        return false;
    }
    const response = parsed as response_envelope_t;
    if (response.status !== 'ok') {
        return false;
    }
    const payload = response.payload as { message?: unknown } | undefined;
    return payload?.message === 'pong';
}

async function RunHeartbeat(params: {
    websocket_url: string;
    settings: fuzz_settings_t;
}): Promise<boolean> {
    const request_text = BuildRequestEnvelope({
        request_id: `heartbeat-${Date.now()}`,
        command: 'ping',
        payload: {}
    });

    const run_result = await RunWebsocketExchange({
        url: params.websocket_url,
        tls_material: params.settings.tls_material,
        include_client_cert: params.settings.transport_profile === 'mtls',
        send_text: request_text,
        wait_ms: params.settings.request_timeout_ms
    });

    return run_result.frames.some((frame) => IsSuccessfulPingResponse({ frame }));
}

async function AssertUnauthorizedConnectionRejected(params: {
    url: string;
    settings: fuzz_settings_t;
    include_client_cert: boolean;
    invariant_name: string;
}): Promise<void> {
    const unauthorized_request = BuildRequestEnvelope({
        request_id: `${params.invariant_name}-ping`,
        command: 'ping',
        payload: {}
    });
    const run_result = await RunWebsocketExchange({
        url: params.url,
        tls_material: params.settings.tls_material,
        include_client_cert: params.include_client_cert,
        send_text: unauthorized_request,
        wait_ms: params.settings.request_timeout_ms
    });

    const unauthorized_success = run_result.frames.some((frame) => IsSuccessfulPingResponse({ frame }));
    if (unauthorized_success) {
        throw new Error(`security invariant failed: unauthorized request succeeded (${params.invariant_name})`);
    }
}

async function RunSecurityInvariants(params: {
    websocket_base_url: string;
    websocket_authed_url: string;
    settings: fuzz_settings_t;
}): Promise<void> {
    const wrong_token_url = BuildAuthedUrl({
        base_url: params.websocket_base_url,
        token: `${params.settings.auth_token}_wrong`
    });

    await AssertUnauthorizedConnectionRejected({
        url: params.websocket_base_url,
        settings: params.settings,
        include_client_cert: params.settings.transport_profile === 'mtls',
        invariant_name: 'missing_token'
    });

    await AssertUnauthorizedConnectionRejected({
        url: wrong_token_url,
        settings: params.settings,
        include_client_cert: params.settings.transport_profile === 'mtls',
        invariant_name: 'invalid_token'
    });

    if (params.settings.require_mtls) {
        const mtls_missing_cert_result = await RunWebsocketExchange({
            url: params.websocket_authed_url,
            tls_material: params.settings.tls_material,
            include_client_cert: false,
            send_text: BuildRequestEnvelope({
                request_id: 'mtls-negative',
                command: 'ping',
                payload: {}
            }),
            wait_ms: params.settings.request_timeout_ms
        });
        const mtls_bypass = mtls_missing_cert_result.frames.some((frame) => IsSuccessfulPingResponse({ frame }));
        if (mtls_bypass) {
            throw new Error('security invariant failed: mTLS connection succeeded without client certificate');
        }
    }
}

function BuildReplayTrace(params: { replay_case_path: string }): fuzz_trace_entry_t[] {
    const raw_text = readFileSync(params.replay_case_path, 'utf8');
    const parsed = JSON.parse(raw_text) as replay_case_t;
    if (!Array.isArray(parsed.trace) || parsed.trace.length === 0) {
        throw new Error(`Invalid replay trace at ${params.replay_case_path}`);
    }
    return parsed.trace;
}

async function ExecuteAction(params: {
    action_entry: fuzz_trace_entry_t;
    state: fuzz_state_t;
    settings: fuzz_settings_t;
    websocket_authed_url: string;
}): Promise<void> {
    if (params.action_entry.action_kind === 'parallel_subscription_storm') {
        const storm_results = await ExecuteParallelSubscriptionStorm({
            request_text: params.action_entry.request_text ?? '',
            websocket_url: params.websocket_authed_url,
            settings: params.settings,
            trace_note: params.action_entry.note
        });
        for (const result of storm_results) {
            for (const frame of result.frames) {
                RegisterFrameEffects({
                    frame_text: frame,
                    state: params.state
                });
            }
        }
        return;
    }

    const run_result = await RunWebsocketExchange({
        url: params.websocket_authed_url,
        tls_material: params.settings.tls_material,
        include_client_cert: params.settings.transport_profile === 'mtls',
        send_text: params.action_entry.request_text,
        wait_ms: params.action_entry.wait_ms
    });

    for (const frame of run_result.frames) {
        RegisterFrameEffects({
            frame_text: frame,
            state: params.state
        });
    }

    if (params.action_entry.expect_response && run_result.frames.length === 0) {
        params.state.summary.daemon_unresponsive_failures += 1;
        throw new Error(`expected response but received none for ${params.action_entry.note}`);
    }
}

async function CancelKnownJobs(params: {
    websocket_authed_url: string;
    state: fuzz_state_t;
    settings: fuzz_settings_t;
}): Promise<void> {
    for (const job_id of params.state.known_job_ids) {
        if (params.state.known_terminal_jobs.has(job_id)) {
            continue;
        }
        const request_text = BuildRequestEnvelope({
            request_id: `cleanup-cancel-${job_id}`,
            command: 'cancel_job',
            payload: { job_id }
        });
        await RunWebsocketExchange({
            url: params.websocket_authed_url,
            tls_material: params.settings.tls_material,
            include_client_cert: params.settings.transport_profile === 'mtls',
            send_text: request_text,
            wait_ms: 400
        });
    }
}

function CreateState(params: { settings: fuzz_settings_t }): fuzz_state_t {
    return {
        request_counter: 1,
        known_job_ids: [],
        known_terminal_jobs: new Set<string>(),
        last_event_ids: new Map<string, number>(),
        summary: {
            success: false,
            transport_profile: params.settings.transport_profile,
            seed: params.settings.replay_seed ?? params.settings.seed,
            replay_mode: Boolean(params.settings.replay_case_path),
            iterations_attempted: 0,
            valid_responses: 0,
            error_responses: 0,
            event_messages: 0,
            invariant_failures: 0,
            daemon_unresponsive_failures: 0,
            started_jobs: 0,
            runtime_ms: 0,
            artifact_dir: params.settings.artifact_dir
        }
    };
}

function EnsureArtifactDirectory(params: { artifact_dir: string }): void {
    mkdirSync(params.artifact_dir, { recursive: true });
}

function WriteArtifacts(params: {
    artifact_dir: string;
    summary: fuzz_summary_t;
    trace: fuzz_trace_entry_t[];
    failure_case?: { error: string; trace: fuzz_trace_entry_t[] };
}): void {
    EnsureArtifactDirectory({ artifact_dir: params.artifact_dir });
    writeFileSync(
        ResolvePath(params.artifact_dir, 'summary.json'),
        `${JSON.stringify(params.summary, null, 2)}\n`,
        'utf8'
    );
    writeFileSync(
        ResolvePath(params.artifact_dir, 'trace.json'),
        `${JSON.stringify({ trace: params.trace }, null, 2)}\n`,
        'utf8'
    );
    if (params.failure_case) {
        writeFileSync(
            ResolvePath(params.artifact_dir, 'failure_case.json'),
            `${JSON.stringify(params.failure_case, null, 2)}\n`,
            'utf8'
        );
    }
}

async function RunFuzzCampaign(params: { settings: fuzz_settings_t }): Promise<void> {
    const started_ms = Date.now();
    const replay_trace = params.settings.replay_case_path
        ? BuildReplayTrace({ replay_case_path: params.settings.replay_case_path })
        : undefined;
    const rng_seed = params.settings.replay_seed ?? params.settings.seed;
    const rng = new DeterministicRng({ seed: rng_seed });

    const websocket_authed_url = BuildAuthedUrl({
        base_url: params.settings.base_url,
        token: params.settings.auth_token
    });

    const state = CreateState({ settings: params.settings });
    const trace_entries: fuzz_trace_entry_t[] = [];

    try {
        await RunSecurityInvariants({
            websocket_base_url: params.settings.base_url,
            websocket_authed_url,
            settings: params.settings
        });

        const replay_mode = Boolean(replay_trace);
        const max_iterations = replay_mode ? (replay_trace?.length ?? 0) : params.settings.iterations;

        for (let iteration = 0; iteration < max_iterations; iteration += 1) {
            const elapsed_ms = Date.now() - started_ms;
            if (!replay_mode && elapsed_ms >= params.settings.time_budget_ms) {
                break;
            }

            const request_id = `fuzz-${state.request_counter}`;
            state.request_counter += 1;

            let action_entry: fuzz_trace_entry_t;
            if (replay_mode && replay_trace) {
                action_entry = replay_trace[iteration];
            } else {
                const action_kind = PickWeightedAction({ rng });
                let request_text = '';
                let note = '';
                let wait_ms = 600;
                let expect_response = false;

                if (action_kind === 'valid_command') {
                    const valid_request = BuildValidCommandRequest({
                        state,
                        request_id,
                        rng,
                        scan_target: params.settings.scan_target
                    });
                    request_text = valid_request.request_text;
                    note = valid_request.note;
                    wait_ms = valid_request.wait_ms;
                    expect_response = true;
                } else {
                    const mutated = BuildMutatedRequest({
                        action_kind,
                        request_id,
                        state,
                        rng
                    });
                    request_text = mutated.request_text;
                    note = mutated.note;
                    wait_ms = mutated.wait_ms;
                    expect_response = mutated.expect_response;
                }

                action_entry = {
                    iteration,
                    action_kind,
                    request_text,
                    request_id,
                    wait_ms,
                    expect_response,
                    note
                };
            }

            trace_entries.push(action_entry);
            await ExecuteAction({
                action_entry,
                state,
                settings: params.settings,
                websocket_authed_url
            });
            state.summary.iterations_attempted += 1;

            if (iteration % params.settings.heartbeat_interval === 0) {
                const heartbeat_ok = await RunHeartbeat({
                    websocket_url: websocket_authed_url,
                    settings: params.settings
                });
                if (!heartbeat_ok) {
                    state.summary.daemon_unresponsive_failures += 1;
                    throw new Error('daemon heartbeat failed during fuzz campaign');
                }
            }
        }

        await CancelKnownJobs({
            websocket_authed_url,
            state,
            settings: params.settings
        });

        state.summary.runtime_ms = Date.now() - started_ms;
        state.summary.success = true;
        WriteArtifacts({
            artifact_dir: params.settings.artifact_dir,
            summary: state.summary,
            trace: trace_entries
        });

        process.stdout.write(`fuzz_success=true\n`);
        process.stdout.write(`fuzz_iterations_attempted=${state.summary.iterations_attempted}\n`);
        process.stdout.write(`fuzz_seed=${rng_seed}\n`);
        process.stdout.write(`fuzz_artifact_dir=${params.settings.artifact_dir}\n`);
    } catch (error) {
        state.summary.runtime_ms = Date.now() - started_ms;
        state.summary.success = false;
        state.summary.invariant_failures += 1;
        state.summary.failure_reason = error instanceof Error ? error.message : String(error);

        WriteArtifacts({
            artifact_dir: params.settings.artifact_dir,
            summary: state.summary,
            trace: trace_entries,
            failure_case: {
                error: state.summary.failure_reason,
                trace: trace_entries
            }
        });

        process.stderr.write(`fuzz_success=false\n`);
        process.stderr.write(`fuzz_failure_reason=${state.summary.failure_reason}\n`);
        process.stderr.write(`fuzz_seed=${rng_seed}\n`);
        process.stderr.write(`fuzz_artifact_dir=${params.settings.artifact_dir}\n`);
        throw error;
    }
}

async function Main(): Promise<void> {
    const settings = ParseCliArgs({ argv: process.argv.slice(2) });
    await RunFuzzCampaign({ settings });
}

void Main().catch((error: unknown) => {
    const error_text = error instanceof Error ? error.message : String(error);
    process.stderr.write(`websocket_fuzz_runner_error=${error_text}\n`);
    process.exit(1);
});
