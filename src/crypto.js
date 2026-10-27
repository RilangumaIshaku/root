/* Ephemeral key material. Nothing here is stored anywhere but process memory,
   and every buffer we hand around can be zeroed with wipe(). */

const enc = new TextEncoder();
const dec = new TextDecoder();

export const utf8 = (s) => enc.encode(s);
export const fromUtf8 = (b) => dec.decode(b);

const HKDF_INFO = utf8('ROOT-PORTAL/v1');
const SHA256_LEN = 32;

/* HKDF (RFC 5869) written out over WebCrypto HMAC rather than handed to
   subtle.deriveBits: the HKDF importKey usage rules differ between engines,
   and this way there is exactly one behaviour to test. */
async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

async function hkdf(ikm, salt, info, length) {
  const prk = await hmac(salt.length ? salt : new Uint8Array(SHA256_LEN), ikm);
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
  for (let i = 1, off = 0; off < length; i++) {
    const block = new Uint8Array(prev.length + info.length + 1);
    block.set(prev, 0);
    block.set(info, prev.length);
    block[prev.length + info.length] = i;
    prev = await hmac(prk, block);
    const take = Math.min(prev.length, length - off);
    out.set(prev.subarray(0, take), off);
    off += take;
  }
  wipe(prk, prev);
  return out;
}

export function randomHex(byteLen) {
  const a = crypto.getRandomValues(new Uint8Array(byteLen));
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  return Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
}

export function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromBase64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Overwrite a buffer in place. Best-effort: it clears the bytes we hold, not
    any copy an engine may have made. Strings are immutable in JS, so passing
    one is a deliberate no-op — never materialise a secret as a string if you
    need it gone. */
export function wipe(...bufs) {
  for (const b of bufs) {
    if (!b || typeof b === 'string') continue;
    if (b instanceof ArrayBuffer) { new Uint8Array(b).fill(0); continue; }
    if (b.buffer && typeof b.byteLength === 'number') {
      new Uint8Array(b.buffer, b.byteOffset, b.byteLength).fill(0);
    }
  }
}

/* HKDF-SHA-256 from the shared passphrase, salted with the transfer id.
   Two people who type the same passphrase over the same transfer id land on
   the same AES-GCM key; nobody else can derive it from the QR stream alone. */
async function deriveBits(passphrase, saltHex) {
  // 256 bits of key material, i.e. 32 bytes — HKDF expands in bytes.
  return hkdf(utf8(passphrase), hexToBytes(saltHex), HKDF_INFO, 32);
}

export async function deriveKey(passphrase, saltHex, usages) {
  const bits = await deriveBits(passphrase, saltHex);
  const key = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, usages);
  wipe(bits);
  return key;
}

/** Short public verifier so both ends can confirm the passphrase without
    transmitting it. Same value => same key. Different => mismatch. */
export async function fingerprint(passphrase, saltHex) {
  const bits = await deriveBits(passphrase, saltHex);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bits));
  wipe(bits);
  return bytesToHex(digest.subarray(0, 6));
}

/** 12-byte nonce: transfer id (8) || frame index (4). Unique per key. */
export function nonce(saltHex, index) {
  const iv = new Uint8Array(12);
  iv.set(hexToBytes(saltHex), 0);
  const dv = new DataView(iv.buffer);
  dv.setUint32(8, index >>> 0, false);
  return iv;
}

export async function encryptChunk(key, saltHex, index, aad, plain) {
  const buf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce(saltHex, index), additionalData: aad, tagLength: 128 },
    key,
    plain,
  );
  return new Uint8Array(buf);
}

export async function decryptChunk(key, saltHex, index, aad, cipher) {
  const buf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce(saltHex, index), additionalData: aad, tagLength: 128 },
    key,
    cipher,
  );
  return new Uint8Array(buf);
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
