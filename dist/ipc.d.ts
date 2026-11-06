export type Sender = {
    frameId: number;
    url: string;
};
export type IpcRequest = {
    id: string;
    channel: string;
    sender: Sender;
    payload: Record<string, unknown>;
};
export type AuditEvent = {
    id: string;
    channel: string;
    allowed: boolean;
    reason: string;
    timestamp: string;
};
export declare class DesktopIpcBroker {
    private readonly nonces;
    private readonly audit;
    authorize(request: IpcRequest): {
        allowed: boolean;
        reason: string;
    };
    execute(request: IpcRequest, handler: () => string): {
        ok: boolean;
        result?: string;
        reason?: string;
    };
    auditLog(): AuditEvent[];
}
export declare function redactForLog(value: string): string;
