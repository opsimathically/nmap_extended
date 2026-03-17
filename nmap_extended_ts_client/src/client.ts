import {
    client_settings_t,
    command_name_t,
    event_envelope_t,
    event_handler_t,
    get_daemon_diagnostics_response_payload_t,
    get_capabilities_payload_t,
    get_job_diagnostics_response_payload_t,
    get_job_payload_t,
    get_job_response_payload_t,
    IsEventEnvelope,
    IsResponseEnvelope,
    json_object_t,
    list_jobs_response_payload_t,
    ping_response_payload_t,
    response_envelope_t,
    start_scan_payload_t,
    start_scan_response_payload_t,
    subscribe_events_payload_t,
    CreateRequestEnvelope
} from './types';
import { ControlPlaneClientError } from './errors';
import { BuildAuthedWebsocketUrl, ValidateTransportSecurity } from './auth';
import { WebsocketTransport } from './transport';

type pending_request_t = {
    resolve: (response: response_envelope_t) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
};

export class NmapControlPlaneClient {
    private readonly websocket_url: string;
    private readonly request_timeout_ms: number;

    private readonly command_transport: WebsocketTransport;
    private readonly pending_requests: Map<string, pending_request_t>;
    private readonly event_handlers: Set<event_handler_t>;
    private readonly job_last_event_id: Map<string, number>;

    private request_counter: number;

    constructor(params: client_settings_t) {
        const allow_insecure_ws = params.allow_insecure_ws ?? false;
        this.websocket_url = BuildAuthedWebsocketUrl({
            base_url: params.base_url,
            auth_token: params.auth_token
        });
        ValidateTransportSecurity({
            websocket_url: this.websocket_url,
            allow_insecure_ws
        });

        this.request_timeout_ms = params.request_timeout_ms ?? 15_000;
        this.pending_requests = new Map<string, pending_request_t>();
        this.event_handlers = new Set<event_handler_t>();
        this.job_last_event_id = new Map<string, number>();
        this.request_counter = 1;

        this.command_transport = new WebsocketTransport({
            websocket_url: this.websocket_url,
            reconnect_settings: params.reconnect_settings,
            websocket_tls_settings: params.websocket_tls_settings
        });

        this.command_transport.setHandlers({
            handlers: {
                on_message: (text_message: string) => {
                    this.handleInboundMessage({ text_message });
                },
                on_close: () => {
                    this.failPendingRequests({
                        error: new ControlPlaneClientError({
                            code: 'command_channel_closed',
                            message: 'Command websocket channel closed'
                        })
                    });
                }
            }
        });
    }

    async connect(): Promise<void> {
        await this.command_transport.connect();
    }

    disconnect(): void {
        this.command_transport.disconnect();
        this.failPendingRequests({
            error: new ControlPlaneClientError({
                code: 'client_disconnected',
                message: 'Client disconnected'
            })
        });
    }

    onEvent(params: { handler: event_handler_t }): () => void {
        this.event_handlers.add(params.handler);
        return () => {
            this.event_handlers.delete(params.handler);
        };
    }

    getLastEventId(params: { job_id: string }): number {
        return this.job_last_event_id.get(params.job_id) ?? 0;
    }

    async ping(): Promise<ping_response_payload_t> {
        const response = await this.sendCommand({ command: 'ping', payload: {} });
        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'ping_failed',
                message: response.error ?? 'Ping failed'
            });
        }

        return response.payload as ping_response_payload_t;
    }

    async getCapabilities(): Promise<get_capabilities_payload_t> {
        const response = await this.sendCommand({ command: 'get_capabilities', payload: {} });
        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'get_capabilities_failed',
                message: response.error ?? 'get_capabilities failed'
            });
        }

        return response.payload as get_capabilities_payload_t;
    }

    async startScan(params: start_scan_payload_t): Promise<start_scan_response_payload_t> {
        this.validateScanArgs({ args: params.args });
        this.validateTimeoutMs({ timeout_ms: params.timeout_ms });

        const start_scan_payload: json_object_t = { args: params.args };
        if (typeof params.timeout_ms === 'number') {
            start_scan_payload.timeout_ms = params.timeout_ms;
        }

        const response = await this.sendCommand({
            command: 'start_scan',
            payload: start_scan_payload
        });
        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'start_scan_failed',
                message: response.error ?? 'start_scan failed'
            });
        }

        return response.payload as start_scan_response_payload_t;
    }

    async getJob(params: get_job_payload_t): Promise<get_job_response_payload_t> {
        const response = await this.sendCommand({
            command: 'get_job',
            payload: { job_id: params.job_id }
        });
        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'get_job_failed',
                message: response.error ?? 'get_job failed'
            });
        }

        return response.payload as get_job_response_payload_t;
    }

    async listJobs(): Promise<list_jobs_response_payload_t> {
        const response = await this.sendCommand({ command: 'list_jobs', payload: {} });
        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'list_jobs_failed',
                message: response.error ?? 'list_jobs failed'
            });
        }

        return response.payload as list_jobs_response_payload_t;
    }

    async getDaemonDiagnostics(): Promise<get_daemon_diagnostics_response_payload_t> {
        const response = await this.sendCommand({
            command: 'get_daemon_diagnostics',
            payload: {}
        });
        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'get_daemon_diagnostics_failed',
                message: response.error ?? 'get_daemon_diagnostics failed'
            });
        }

        return response.payload as get_daemon_diagnostics_response_payload_t;
    }

    async getJobDiagnostics(params: get_job_payload_t): Promise<get_job_diagnostics_response_payload_t> {
        const response = await this.sendCommand({
            command: 'get_job_diagnostics',
            payload: { job_id: params.job_id }
        });
        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'get_job_diagnostics_failed',
                message: response.error ?? 'get_job_diagnostics failed'
            });
        }

        return response.payload as get_job_diagnostics_response_payload_t;
    }

    async cancelJob(params: get_job_payload_t): Promise<void> {
        const response = await this.sendCommand({
            command: 'cancel_job',
            payload: { job_id: params.job_id }
        });

        if (response.status !== 'ok') {
            throw new ControlPlaneClientError({
                code: 'cancel_job_failed',
                message: response.error ?? 'cancel_job failed'
            });
        }
    }

    async subscribeEvents(params: {
        job_id: string;
        last_event_id?: number;
        handler?: event_handler_t;
    }): Promise<void> {
        const initial_last_event_id = params.last_event_id
            ?? this.job_last_event_id.get(params.job_id)
            ?? 0;

        const subscribe_payload: subscribe_events_payload_t = {
            job_id: params.job_id,
            last_event_id: initial_last_event_id
        };

        const subscription_transport = new WebsocketTransport({
            websocket_url: this.websocket_url,
            reconnect_settings: {
                enabled: false,
                initial_delay_ms: 100,
                max_delay_ms: 200,
                jitter_ratio: 0
            }
        });

        return new Promise<void>((resolve, reject) => {
            const request_id = this.createRequestId();
            let has_terminal_event = false;
            let settled = false;

            const settleResolve = () => {
                if (settled) {
                    return;
                }
                settled = true;
                subscription_transport.disconnect();
                resolve();
            };

            const settleReject = (error: Error) => {
                if (settled) {
                    return;
                }
                settled = true;
                subscription_transport.disconnect();
                reject(error);
            };

            subscription_transport.setHandlers({
                handlers: {
                    on_open: () => {
                        const request = CreateRequestEnvelope({
                            request_id: request_id,
                            command: 'subscribe_events',
                            payload: subscribe_payload as unknown as json_object_t
                        });
                        subscription_transport.sendJson({ payload: request });
                    },
                    on_message: (text_message: string) => {
                        let parsed_message: unknown;
                        try {
                            parsed_message = JSON.parse(text_message);
                        } catch {
                            settleReject(new ControlPlaneClientError({
                                code: 'invalid_json',
                                message: 'Received invalid JSON on event stream'
                            }));
                            return;
                        }

                        if (IsResponseEnvelope(parsed_message)) {
                            const response = parsed_message;
                            if (response.request_id !== request_id) {
                                return;
                            }

                            if (response.status === 'error') {
                                settleReject(new ControlPlaneClientError({
                                    code: 'subscribe_events_failed',
                                    message: response.error ?? 'subscribe_events failed'
                                }));
                            }
                            return;
                        }

                        if (IsEventEnvelope(parsed_message)) {
                            const event_message = parsed_message;
                            this.handleEvent({ event_message });
                            params.handler?.(event_message);

                            if (event_message.event_type === 'job_completed'
                                || event_message.event_type === 'job_failed'
                                || event_message.event_type === 'job_canceled'
                                || event_message.event_type === 'job_timeout') {
                                has_terminal_event = true;
                                settleResolve();
                            }
                        }
                    },
                    on_close: () => {
                        if (!has_terminal_event) {
                            settleReject(new ControlPlaneClientError({
                                code: 'event_stream_closed',
                                message: 'Event subscription channel closed before terminal event'
                            }));
                        }
                    },
                    on_error: (error: Error) => {
                        settleReject(error);
                    }
                }
            });

            void subscription_transport.connect().catch((error: unknown) => {
                settleReject(error instanceof Error
                    ? error
                    : new ControlPlaneClientError({
                        code: 'event_stream_connect_failed',
                        message: 'Failed to connect event subscription channel'
                    }));
            });
        });
    }

    private async sendCommand(params: {
        command: command_name_t;
        payload: json_object_t;
    }): Promise<response_envelope_t> {
        const request_id = this.createRequestId();
        const request = CreateRequestEnvelope({
            request_id,
            command: params.command,
            payload: params.payload
        });

        return new Promise<response_envelope_t>((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending_requests.delete(request_id);
                reject(new ControlPlaneClientError({
                    code: 'request_timeout',
                    message: `Timed out waiting for response to ${params.command}`
                }));
            }, this.request_timeout_ms);

            this.pending_requests.set(request_id, {
                resolve: (response: response_envelope_t) => {
                    clearTimeout(timer);
                    resolve(response);
                },
                reject: (error: Error) => {
                    clearTimeout(timer);
                    reject(error);
                },
                timer
            });

            try {
                this.command_transport.sendJson({ payload: request });
            } catch (error) {
                clearTimeout(timer);
                this.pending_requests.delete(request_id);
                reject(error instanceof Error
                    ? error
                    : new ControlPlaneClientError({
                        code: 'send_failed',
                        message: 'Failed to send command request'
                    }));
            }
        });
    }

    private handleInboundMessage(params: { text_message: string }): void {
        let parsed_message: unknown;
        try {
            parsed_message = JSON.parse(params.text_message);
        } catch {
            return;
        }

        if (IsResponseEnvelope(parsed_message)) {
            const response = parsed_message;
            const pending_request = this.pending_requests.get(response.request_id);
            if (!pending_request) {
                return;
            }

            this.pending_requests.delete(response.request_id);
            pending_request.resolve(response);
            return;
        }

        if (IsEventEnvelope(parsed_message)) {
            this.handleEvent({ event_message: parsed_message });
        }
    }

    private handleEvent(params: { event_message: event_envelope_t }): void {
        const current_cursor = this.job_last_event_id.get(params.event_message.job_id) ?? 0;
        if (params.event_message.event_id > current_cursor) {
            this.job_last_event_id.set(params.event_message.job_id, params.event_message.event_id);
        }

        for (const handler of this.event_handlers) {
            handler(params.event_message);
        }
    }

    private failPendingRequests(params: { error: Error }): void {
        for (const [request_id, pending_request] of this.pending_requests.entries()) {
            clearTimeout(pending_request.timer);
            pending_request.reject(params.error);
            this.pending_requests.delete(request_id);
        }
    }

    private createRequestId(): string {
        const request_id = `req-${Date.now()}-${this.request_counter}`;
        this.request_counter += 1;
        return request_id;
    }

    private validateScanArgs(params: { args: string[] }): void {
        if (params.args.length === 0) {
            throw new ControlPlaneClientError({
                code: 'invalid_scan_args',
                message: 'start_scan requires at least one scan argument'
            });
        }

        for (const arg of params.args) {
            if (arg.length === 0 || arg.length > 512) {
                throw new ControlPlaneClientError({
                    code: 'invalid_scan_args',
                    message: 'Each scan argument must be 1..512 characters'
                });
            }
            if (arg.includes('\n') || arg.includes('\r')) {
                throw new ControlPlaneClientError({
                    code: 'invalid_scan_args',
                    message: 'Scan arguments may not contain newline characters'
                });
            }
        }
    }

    private validateTimeoutMs(params: { timeout_ms?: number }): void {
        if (typeof params.timeout_ms !== 'number') {
            return;
        }

        if (!Number.isInteger(params.timeout_ms)
            || params.timeout_ms < 1
            || params.timeout_ms > 604_800_000) {
            throw new ControlPlaneClientError({
                code: 'invalid_timeout_ms',
                message: 'timeout_ms must be an integer between 1 and 604800000'
            });
        }
    }
}
