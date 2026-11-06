import { randomUUID } from "node:crypto";

export type Sender = { frameId: number; url: string };
export type IpcRequest = { id: string; channel: string; sender: Sender; payload: Record<string, unknown> };
export type AuditEvent = { id: string; channel: string; allowed: boolean; reason: string; timestamp: string };

const ALLOWED_CHANNELS = new Set(["vault:unlock", "vault:list", "vault:lock", "autotype:run", "ssh:sign"]);
const TRUSTED_ORIGINS = new Set(["app://bitwarden", "https://vault.bitwarden.com"]);
const SENSITIVE_KEYS = /password|secret|token|private|masterKey|key/i;

export class DesktopIpcBroker {
  private readonly nonces = new Set<string>();
  private readonly audit: AuditEvent[] = [];

  authorize(request: IpcRequest): { allowed: boolean; reason: string } {
    const reason = !request.id || !request.channel ? "malformed request"
      : !ALLOWED_CHANNELS.has(request.channel) ? "channel not allowed"
      : !TRUSTED_ORIGINS.has(request.sender.url) ? "untrusted sender"
      : request.sender.frameId !== 0 ? "untrusted frame"
      : this.nonces.has(request.id) ? "replayed request"
      : "ok";
    const allowed = reason === "ok";
    if (allowed) this.nonces.add(request.id);
    this.audit.push({ id: request.id || randomUUID(), channel: request.channel || "unknown", allowed, reason, timestamp: new Date().toISOString() });
    return { allowed, reason };
  }

  execute(request: IpcRequest, handler: () => string): { ok: boolean; result?: string; reason?: string } {
    const check = this.authorize(request);
    if (!check.allowed) return { ok: false, reason: check.reason };
    return { ok: true, result: redactForLog(handler()) };
  }

  auditLog(): AuditEvent[] { return [...this.audit]; }
}

export function redactForLog(value: string): string {
  return value.replace(/"([^"]+)"\s*:\s*"[^"]*"/g, (match, key) => SENSITIVE_KEYS.test(key) ? `"${key}":"[redacted]"` : match);
}
