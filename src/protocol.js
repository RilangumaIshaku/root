/* The wire format for an optical burst.

   One portal carries exactly one message. The message is split into fixed
   size plaintext chunks; each chunk is AES-GCM sealed on its own with the
   frame index bound as additional data, so a reordered or swapped frame is
   rejected rather than silently accepted. A trailer frame carries the SHA-256
   of the whole plaintext plus its length, which is the final integrity check.

   Frame shapes (all UTF-8 JSON, kept small to fit a scannable QR symbol):

     data  {"v":1,"x":"<16 hex>","n":12,"i":3,"p":"<base64 ct>"}
     trailer {"v":1,"x":"<16 hex>","n":12,"i":-1,"h":"<base64 hash>","l":417}
*/

import {
  deriveKey, encryptChunk, decryptChunk, fingerprint,
  randomHex, sha256, toBase64, fromBase64,
  utf8, wipe,
} from './crypto.js';

export const PROTOCOL_VERSION = 1;
export const CHUNK_BYTES = 80;      // plaintext bytes per frame
export const TRAILER = -1;
export const DEFAULT_PASSES = 3;    // ping-pong sweeps across the burst

const MIN_FRAMES = 1;

function aadFor(id, total, index) {
  return utf8(`${PROTOCOL_VERSION}|${id}|${total}|${index}`);
}

function frameString(obj) {
  const s = JSON.stringify(obj);
  if (s.length > 900) {
    throw new Error(`frame too dense for a scannable symbol (${s.length} bytes)`);
  }
  return s;
}

/** Encrypt `text` under `passphrase` and return the ordered frame strings.
    The first element of every sweep is the trailer, so a receiver that joins
    late learns the frame count immediately. */
export async function seal(text, passphrase, id = randomHex(8)) {
  const plain = utf8(text);
  const total = Math.max(MIN_FRAMES, Math.ceil(plain.length / CHUNK_BYTES));

  const key = await deriveKey(passphrase, id, ['encrypt']);
  const frames = [];

  for (let i = 0; i < total; i++) {
    const slice = plain.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES);
    const ct = await encryptChunk(key, id, i, aadFor(id, total, i), slice);
    frames.push(frameString({
      v: PROTOCOL_VERSION, x: id, n: total, i,
      p: toBase64(ct),
    }));
    wipe(ct);
  }

  const digest = toBase64(await sha256(plain));
  const trailer = frameString({
    v: PROTOCOL_VERSION, x: id, n: total, i: TRAILER,
    h: digest, l: plain.length,
  });

  wipe(plain, key);
  return {
    id,
    total,
    trailer,
    frames,
    fingerprint: await fingerprint(passphrase, id),
    bytes: text.length,
  };
}

/** Ping-pong sweep: trailer first, then forward, then reversed, and so on.
    Every frame appears once per pass, so a receiver that locks on late still
    collects the whole message if it stays pointed at the screen. */
export function sweep(trailer, frames, passes = DEFAULT_PASSES) {
  const out = [];
  for (let p = 0; p < passes; p++) {
    out.push(trailer);
    out.push(...(p % 2 === 0 ? frames : [...frames].reverse()));
  }
  return out;
}

export function parseFrame(raw) {
  if (typeof raw !== 'string' || raw.length > 2000) return null;
  let o;
  try { o = JSON.parse(raw); } catch { return null; }
  if (!o || o.v !== PROTOCOL_VERSION) return null;
  if (typeof o.x !== 'string' || !/^[0-9a-f]{16}$/.test(o.x)) return null;
  if (!Number.isInteger(o.n) || o.n < MIN_FRAMES || o.n > 4096) return null;
  if (!Number.isInteger(o.i) || o.i < TRAILER || o.i >= o.n) return null;

  if (o.i === TRAILER) {
    if (typeof o.h !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(o.h)) return null;
    if (!Number.isInteger(o.l) || o.l < 0 || o.l > 1_000_000) return null;
    return { kind: 'trailer', id: o.x, total: o.n, hash: o.h, length: o.l };
  }
  if (typeof o.p !== 'string') return null;
  return { kind: 'data', id: o.x, total: o.n, index: o.i, payload: o.p };
}

/** Accumulates frames for a single portal. Never touches disk or storage. */
export class Reassembly {
  constructor() {
    this.reset();
  }

  reset() {
    this.id = null;
    this.total = 0;
    this.chunks = new Map();
    this.trailer = null;
    this.received = 0;
    this.duplicates = 0;
    this.rejected = 0;
    this.error = null;
  }

  /** Feed one decoded symbol. Returns true if it changed our state. */
  push(raw) {
    const f = parseFrame(raw);
    if (!f) { this.rejected++; return false; }

    // A different transfer id means a new portal opened — drop the old one.
    if (this.id !== null && this.id !== f.id) this.reset();
    if (this.id === null) this.id = f.id;

    if (f.kind === 'trailer') {
      if (this.trailer) { this.duplicates++; return false; }
      this.trailer = { hash: f.hash, length: f.length };
      this.total = f.total;
      return true;
    }

    this.total = f.total;
    if (this.chunks.has(f.index)) { this.duplicates++; return false; }
    this.chunks.set(f.index, f.payload);
    this.received++;
    return true;
  }

  get complete() {
    return !!this.trailer && this.chunks.size >= this.total;
  }

  get progress() {
    if (!this.total) return 0;
    return Math.min(1, this.chunks.size / this.total);
  }

  /** Open the sealed frames under `passphrase` and verify the whole message.
      On any failure the partial plaintext is destroyed and null is returned. */
  async open(passphrase) {
    if (!this.complete) throw new Error('incomplete burst');
    const key = await deriveKey(passphrase, this.id, ['decrypt']);

    const parts = [];
    let plain = null;
    try {
      for (let i = 0; i < this.total; i++) {
        const ct = fromBase64(this.chunks.get(i));
        const pt = await decryptChunk(
          key, this.id, i, aadFor(this.id, this.total, i), ct,
        );
        parts.push(pt);
        wipe(ct);
      }

      plain = new Uint8Array(this.trailer.length);
      let off = 0;
      for (const p of parts) { plain.set(p, off); off += p.length; wipe(p); }
      if (off !== plain.length) throw new Error('length mismatch');

      const digest = toBase64(await sha256(plain));
      if (digest !== this.trailer.hash) throw new Error('integrity check failed');

      return plain;
    } catch (err) {
      for (const p of parts) wipe(p);
      wipe(plain);
      throw err;
    } finally {
      wipe(key);
    }
  }
}
