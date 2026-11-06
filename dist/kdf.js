import { createCipheriv, createDecipheriv, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
export function deriveMasterKey(password, email, config = { algorithm: "pbkdf2-sha256", iterations: 600_000, salt: Buffer.alloc(0) }) {
    if (!password)
        throw new Error("Password is required");
    if (!email.includes("@"))
        throw new Error("A valid email is required");
    if (config.iterations < 100_000)
        throw new Error("KDF iterations below security floor");
    const salt = config.salt.length ? config.salt : Buffer.from(email.trim().toLowerCase(), "utf8");
    return pbkdf2Sync(password, salt, config.iterations, 32, "sha256");
}
export function stretchMasterKey(masterKey) {
    if (masterKey.length !== 32)
        throw new Error("Master key must be 32 bytes");
    return Buffer.from(hkdfSync("sha256", masterKey, Buffer.alloc(0), Buffer.from("bitwarden:vault:v1"), 32));
}
export function encryptItem(plaintext, masterKey, keyVersion = 1) {
    const key = stretchMasterKey(masterKey);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64"), keyVersion };
}
export function decryptItem(item, masterKey) {
    const key = stretchMasterKey(masterKey);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(item.iv, "base64"));
    decipher.setAuthTag(Buffer.from(item.tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(item.ciphertext, "base64")), decipher.final()]).toString("utf8");
}
