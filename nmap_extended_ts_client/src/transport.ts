import WebSocket from 'ws';
import { ControlPlaneClientError } from './errors';
import {
    connection_state_t,
    reconnect_settings_t,
    transport_handlers_i,
    websocket_tls_settings_t
} from './types';

const default_reconnect_settings: reconnect_settings_t = {
    enabled: true,
    initial_delay_ms: 250,
    max_delay_ms: 5_000,
    jitter_ratio: 0.2
};

const default_websocket_tls_settings: websocket_tls_settings_t = {
    reject_unauthorized_tls: true
};

export class WebsocketTransport {
    private readonly websocket_url: string;
    private readonly reconnect_settings: reconnect_settings_t;
    private readonly websocket_tls_settings: websocket_tls_settings_t;

    private handlers: transport_handlers_i;
    private ws_client: WebSocket | null;
    private state: connection_state_t;
    private reconnect_attempt: number;
    private reconnect_timer: NodeJS.Timeout | null;
    private connect_promise: Promise<void> | null;
    private should_reconnect: boolean;

    constructor(params: {
        websocket_url: string;
        reconnect_settings?: reconnect_settings_t;
        websocket_tls_settings?: websocket_tls_settings_t;
    }) {
        this.websocket_url = params.websocket_url;
        this.reconnect_settings = params.reconnect_settings ?? default_reconnect_settings;
        this.websocket_tls_settings = params.websocket_tls_settings ?? default_websocket_tls_settings;

        this.handlers = {};
        this.ws_client = null;
        this.state = 'disconnected';
        this.reconnect_attempt = 0;
        this.reconnect_timer = null;
        this.connect_promise = null;
        this.should_reconnect = this.reconnect_settings.enabled;
    }

    setHandlers(params: { handlers: transport_handlers_i }): void {
        this.handlers = params.handlers;
    }

    getState(): connection_state_t {
        return this.state;
    }

    async connect(): Promise<void> {
        if (this.state === 'connected') {
            return;
        }

        if (this.state === 'connecting' && this.connect_promise) {
            return this.connect_promise;
        }

        this.should_reconnect = this.reconnect_settings.enabled;
        this.state = 'connecting';

        this.connect_promise = new Promise<void>((resolve, reject) => {
            this.ws_client = new WebSocket(this.websocket_url, {
                rejectUnauthorized: this.websocket_tls_settings.reject_unauthorized_tls
            });

            this.ws_client.on('open', () => {
                this.state = 'connected';
                this.reconnect_attempt = 0;
                this.handlers.on_open?.();
                resolve();
            });

            this.ws_client.on('message', (message_buffer: WebSocket.RawData) => {
                const text_message = Buffer.isBuffer(message_buffer)
                    ? message_buffer.toString('utf8')
                    : String(message_buffer);
                this.handlers.on_message?.(text_message);
            });

            this.ws_client.on('error', (error: Error) => {
                this.handlers.on_error?.(error);
                if (this.state === 'connecting') {
                    reject(error);
                }
            });

            this.ws_client.on('close', (close_code: number, close_reason: Buffer) => {
                const reason_text = close_reason.toString('utf8');
                this.state = 'disconnected';
                this.handlers.on_close?.(close_code, reason_text);

                if (this.should_reconnect && this.reconnect_settings.enabled) {
                    this.scheduleReconnect();
                }
            });
        }).finally(() => {
            this.connect_promise = null;
        });

        if (!this.connect_promise) {
            throw new ControlPlaneClientError({
                code: 'connect_internal_error',
                message: 'Internal transport connect promise is unavailable'
            });
        }

        return this.connect_promise;
    }

    disconnect(): void {
        this.should_reconnect = false;

        if (this.reconnect_timer) {
            clearTimeout(this.reconnect_timer);
            this.reconnect_timer = null;
        }

        if (this.ws_client) {
            this.ws_client.close();
            this.ws_client = null;
        }

        this.state = 'disconnected';
    }

    sendJson(params: { payload: unknown }): void {
        if (!this.ws_client || this.state !== 'connected') {
            throw new ControlPlaneClientError({
                code: 'transport_not_connected',
                message: 'Websocket transport is not connected'
            });
        }

        const body = JSON.stringify(params.payload);
        this.ws_client.send(body);
    }

    private scheduleReconnect(): void {
        if (this.reconnect_timer) {
            return;
        }

        const delay_ms = this.calculateReconnectDelay();
        this.reconnect_timer = setTimeout(() => {
            this.reconnect_timer = null;
            void this.connect();
        }, delay_ms);
    }

    private calculateReconnectDelay(): number {
        const exponential_delay = Math.min(
            this.reconnect_settings.initial_delay_ms * Math.pow(2, this.reconnect_attempt),
            this.reconnect_settings.max_delay_ms
        );

        this.reconnect_attempt += 1;

        const jitter_window = exponential_delay * this.reconnect_settings.jitter_ratio;
        const jitter = (Math.random() * 2 - 1) * jitter_window;
        return Math.max(50, Math.floor(exponential_delay + jitter));
    }
}
