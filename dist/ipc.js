import { randomUUID } from "node:crypto";
const ALLOWED_CHANNELS = new Set(["vault:unlock", "vault:list", "vault:lock", "autotype:run", "ssh:sign"]);
const TRUSTED_ORIGINS = new Set(["app://bitwarden", "https://vault.bitwarden.com"]);
const SENSITIVE_KEYS = /password|secret|token|private|masterKey|key/i;
export class DesktopIpcBroker {
    nonces = new Set();
    audit = [];
    authorize(request) {
        const reason = !request.id || !request.channel ? "malformed request"
            : !ALLOWED_CHANNELS.has(request.channel) ? "channel not allowed"
                : !TRUSTED_ORIGINS.has(request.sender.url) ? "untrusted sender"
                    : request.sender.frameId !== 0 ? "untrusted frame"
                        : this.nonces.has(request.id) ? "replayed request"
                            : "ok";
        const allowed = reason === "ok";
        if (allowed)
            this.nonces.add(request.id);
        this.audit.push({ id: request.id || randomUUID(), channel: request.channel || "unknown", allowed, reason, timestamp: new Date().toISOString() });
        return { allowed, reason };
    }
    execute(request, handler) {
        const check = this.authorize(request);
        if (!check.allowed)
            return { ok: false, reason: check.reason };
        return { ok: true, result: redactForLog(handler()) };
    }
    auditLog() { return [...this.audit]; }
}
export function redactForLog(value) {
    return value.replace(/"([^"]+)"\s*:\s*"[^"]*"/g, (match, key) => SENSITIVE_KEYS.test(key) ? `"${key}":"[redacted]"` : match);
}
