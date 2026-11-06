export type KdfConfig = {
    algorithm: "pbkdf2-sha256";
    iterations: number;
    salt: Buffer;
};
export type EncryptedItem = {
    iv: string;
    tag: string;
    ciphertext: string;
    keyVersion: number;
};
export declare function deriveMasterKey(password: string, email: string, config?: KdfConfig): Buffer;
export declare function stretchMasterKey(masterKey: Buffer): Buffer;
export declare function encryptItem(plaintext: string, masterKey: Buffer, keyVersion?: number): EncryptedItem;
export declare function decryptItem(item: EncryptedItem, masterKey: Buffer): string;
