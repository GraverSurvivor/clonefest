/**
 * Client-side only Web Crypto utilities.
 * These run exclusively in the browser — never on the server.
 */

// ---------- Buffer / Base64 ----------

export function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToBuffer(base64: string): ArrayBuffer {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------- AES-256-GCM ----------

export async function generateAESKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function exportKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bufferToBase64(raw);
}

export async function importKey(base64Key: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    base64ToBuffer(base64Key),
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptData(
  plaintext: string,
  key: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    encoded
  );
  return { ciphertext: bufferToBase64(ciphertext), iv: bufferToBase64(iv.buffer as ArrayBuffer) };
}

export async function decryptData(
  ciphertextB64: string,
  ivB64: string,
  key: CryptoKey
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuffer(ivB64) as ArrayBuffer },
    key,
    base64ToBuffer(ciphertextB64) as ArrayBuffer
  );
  return new TextDecoder().decode(decrypted);
}

// ---------- PBKDF2 key wrapping ----------

async function deriveWrappingKey(
  password: string,
  salt: BufferSource
): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function wrapPrimaryKey(
  primaryKey: CryptoKey,
  password: string,
  salt: Uint8Array
): Promise<{ wrapped_key: string; key_iv: string }> {
  const wrappingKey = await deriveWrappingKey(password, salt.buffer as ArrayBuffer);
  const rawKey = await crypto.subtle.exportKey("raw", primaryKey) as ArrayBuffer;
  const keyIv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedKey = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: keyIv.buffer as ArrayBuffer },
    wrappingKey,
    rawKey
  );
  return {
    wrapped_key: bufferToBase64(encryptedKey),
    key_iv: bufferToBase64(keyIv.buffer as ArrayBuffer),
  };
}

export async function unwrapPrimaryKey(
  wrappedKeyB64: string,
  keyIvB64: string,
  password: string,
  saltB64: string
): Promise<CryptoKey> {
  const wrappingKey = await deriveWrappingKey(password, base64ToBuffer(saltB64) as ArrayBuffer);
  const rawKey = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuffer(keyIvB64) as ArrayBuffer },
    wrappingKey,
    base64ToBuffer(wrappedKeyB64) as ArrayBuffer
  );
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
}
