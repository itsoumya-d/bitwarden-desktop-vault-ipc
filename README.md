# bitwarden-desktop-vault-ipc

Reference implementation of the security boundary between an Electron renderer and a password-manager desktop main process. It mirrors Bitwarden's desktop concerns: master-key derivation, vault item encryption, secure IPC authorization, replay protection, audit logging, autotype sequences and redaction.

## Stack

- TypeScript 5 / Node.js 22
- AES-256-GCM, PBKDF2-SHA256, HKDF
- Zero-knowledge vault model
- Node test runner and GitHub Actions CI

## Run

```bash
npm install
npm test
```

## Security properties

- 600k PBKDF2-SHA256 iterations in production, with a hard 100k floor.
- 32-byte master key stretched with HKDF before item encryption.
- Fresh 96-bit IV for every item; authentication tags verified on decrypt.
- IPC allowlist, trusted-origin and top-frame checks, one-time request IDs.
- Secret-key redaction before any log sink.
- Autotype parser validates every field before emitting keystrokes.
