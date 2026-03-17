export class ControlPlaneClientError extends Error {
    public readonly code: string;

    constructor(params: { message: string; code: string }) {
        super(params.message);
        this.name = 'ControlPlaneClientError';
        this.code = params.code;
    }
}
