export type command_name_t =
    | 'ping'
    | 'get_capabilities'
    | 'start_scan'
    | 'get_job'
    | 'list_jobs'
    | 'cancel_job'
    | 'subscribe_events'
    | 'get_daemon_diagnostics'
    | 'get_job_diagnostics';

export type response_status_t = 'ok' | 'error';

export type event_type_t =
    | 'job_queued'
    | 'job_started'
    | 'host_discovered'
    | 'host_state_changed'
    | 'port_state_changed'
    | 'service_discovered'
    | 'os_match_candidate'
    | 'os_discovered'
    | 'traceroute_hop'
    | 'script_result'
    | 'scan_warning'
    | 'scan_error'
    | 'job_progress'
    | 'job_completed'
    | 'job_failed'
    | 'job_canceled'
    | 'job_timeout'
    | 'stream_backpressure'
    | 'event_loss';

export type json_value_t = string | number | boolean | null | json_object_t | json_array_t;
export type json_object_t = { [key: string]: json_value_t };
export type json_array_t = json_value_t[];

export type request_envelope_t = {
    request_id: string;
    command: command_name_t;
    payload: json_object_t;
};

export type response_envelope_t = {
    request_id: string;
    status: response_status_t;
    payload: json_value_t;
    error?: string;
};

export type event_envelope_t = {
    event_id: number;
    job_id: string;
    event_type: event_type_t;
    ts: string;
    payload: json_value_t;
};

export type event_handler_t = (event_message: event_envelope_t) => void;

export type ping_response_payload_t = {
    message: string;
};

export type get_capabilities_payload_t = {
    commands: string[];
    max_concurrent_scans: number;
    event_delivery: string;
    wss_supported: boolean;
    mtls_supported: boolean;
};

export type start_scan_payload_t = {
    args: string[];
    timeout_ms?: number;
};

export type start_scan_response_payload_t = {
    job_id: string;
    status: string;
    timeout_requested: boolean;
    timeout_ms?: number;
};

export type get_job_payload_t = {
    job_id: string;
};

export type get_job_response_payload_t = {
    job_id: string;
    status: string;
    exit_code: number;
};

export type list_jobs_response_payload_t = {
    jobs: get_job_response_payload_t[];
};

export type daemon_limits_t = {
    bind_addr: string;
    port: number;
    max_event_buffer: number;
    max_active_scans: number;
    cancel_grace_ms: number;
    auth_provider: string;
    tls_enabled: boolean;
    tls_require_client_cert: boolean;
    tls_min_tls_version: string;
};

export type daemon_transport_t = {
    mode: 'ws' | 'wss';
    tls_enabled: boolean;
    require_client_cert: boolean;
    min_tls_version: string;
    cert_material_loaded: boolean;
    ca_configured: boolean;
    allow_insecure_remote_ws: boolean;
};

export type daemon_counters_t = {
    total_events: number;
    total_warnings: number;
    total_errors: number;
    total_backpressure: number;
    total_event_loss: number;
    jobs_queued: number;
    jobs_started: number;
    jobs_completed: number;
    jobs_failed: number;
    jobs_canceled: number;
    jobs_timeout: number;
};

export type get_daemon_diagnostics_response_payload_t = {
    pid: number;
    daemon_version: string;
    binary_path: string;
    started_at: string;
    uptime_sec: number;
    scheduler_health: string;
    queue_depth: number;
    active_jobs: number;
    total_jobs: number;
    websocket_sessions: number;
    limits: daemon_limits_t;
    transport: daemon_transport_t;
    counters: daemon_counters_t;
};

export type job_diagnostics_flags_t = {
    cancel_requested: boolean;
    timeout_requested: boolean;
    timeout_triggered: boolean;
    cancel_escalated: boolean;
};

export type job_diagnostics_timing_t = {
    created_time: number;
    started_time: number;
    ended_time: number;
    elapsed_ms: number;
    timeout_ms: number;
};

export type get_job_diagnostics_response_payload_t = {
    job_id: string;
    status: string;
    phase: string;
    worker_pid: number;
    exit_code: number;
    raw_wait_status: number;
    flags: job_diagnostics_flags_t;
    timing: job_diagnostics_timing_t;
    last_event_id: number;
    buffered_events: number;
    dropped_events: number;
    event_counts: Record<string, number>;
    warning_count: number;
    error_count: number;
    backpressure_count: number;
    event_loss_count: number;
    recent_warnings: string[];
    recent_errors: string[];
};

export type subscribe_events_payload_t = {
    job_id: string;
    last_event_id?: number;
};

export type connection_state_t = 'disconnected' | 'connecting' | 'connected';

export type reconnect_settings_t = {
    enabled: boolean;
    initial_delay_ms: number;
    max_delay_ms: number;
    jitter_ratio: number;
};

export interface transport_handlers_i {
    on_open?: () => void;
    on_message?: (text_message: string) => void;
    on_close?: (close_code: number, close_reason: string) => void;
    on_error?: (error: Error) => void;
}

export type websocket_tls_settings_t = {
    reject_unauthorized_tls: boolean;
    ca_file?: string;
    client_cert_file?: string;
    client_key_file?: string;
    server_name?: string;
};

export type client_settings_t = {
    base_url: string;
    auth_token: string;
    request_timeout_ms?: number;
    allow_insecure_ws?: boolean;
    reconnect_settings?: reconnect_settings_t;
    websocket_tls_settings?: websocket_tls_settings_t;
};

export function CreateRequestEnvelope(params: {
    request_id: string;
    command: command_name_t;
    payload?: json_object_t;
}): request_envelope_t {
    return {
        request_id: params.request_id,
        command: params.command,
        payload: params.payload ?? {}
    };
}

export function IsResponseEnvelope(value: unknown): value is response_envelope_t {
    const candidate = value as Partial<response_envelope_t>;
    return typeof candidate === 'object'
        && candidate !== null
        && typeof candidate.request_id === 'string'
        && (candidate.status === 'ok' || candidate.status === 'error')
        && Object.prototype.hasOwnProperty.call(candidate, 'payload');
}

export function IsEventEnvelope(value: unknown): value is event_envelope_t {
    const candidate = value as Partial<event_envelope_t>;
    return typeof candidate === 'object'
        && candidate !== null
        && typeof candidate.event_id === 'number'
        && Number.isFinite(candidate.event_id)
        && typeof candidate.job_id === 'string'
        && typeof candidate.event_type === 'string'
        && typeof candidate.ts === 'string'
        && Object.prototype.hasOwnProperty.call(candidate, 'payload');
}
