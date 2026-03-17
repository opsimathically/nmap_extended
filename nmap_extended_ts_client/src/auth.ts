import { ControlPlaneClientError } from './errors';

export function BuildAuthedWebsocketUrl(params: { base_url: string; auth_token: string }): string {
    let url: URL;
    try {
        url = new URL(params.base_url);
    } catch {
        throw new ControlPlaneClientError({
            code: 'invalid_url',
            message: `Invalid control-plane URL: ${params.base_url}`
        });
    }

    url.searchParams.set('token', params.auth_token);
    return url.toString();
}

export function ValidateTransportSecurity(params: {
    websocket_url: string;
    allow_insecure_ws: boolean;
}): void {
    const parsed_url = new URL(params.websocket_url);
    const scheme = parsed_url.protocol.toLowerCase();

    if (scheme !== 'wss:' && scheme !== 'ws:') {
        throw new ControlPlaneClientError({
            code: 'unsupported_scheme',
            message: `Unsupported websocket scheme: ${scheme}`
        });
    }

    if (scheme === 'ws:' && !params.allow_insecure_ws) {
        throw new ControlPlaneClientError({
            code: 'insecure_transport_disallowed',
            message: 'ws:// is disabled by default; set allow_insecure_ws=true for explicit local testing'
        });
    }
}
