/* Receiver: point a camera (or a captured screen) at the flashing symbols.

   Decoding prefers the native BarcodeDetector when the browser ships one and
   falls back to jsQR, which runs everywhere. Whatever the source, every
   successful decode is handed to the caller as the raw symbol payload — no
   frame is retained here. */

import jsQR from 'jsqr';
import { renderSymbol } from './sender.js';

const MAX_DECODE_WIDTH = 720;

/** Decode a still symbol straight off a canvas — the self-test path: it
    proves the transmitter's painted pixels are readable by the same decoder
    the camera feed goes through, without needing a second device. */
export function decodeCanvas(canvas) {
  const img = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
  const hit = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
  return hit ? hit.data : null;
}

export class Receiver {
  constructor({ video, onFrame, onStatus }) {
    this.video = video;
    this.onFrame = onFrame || (() => {});
    this.onStatus = onStatus || (() => {});
    this.stream = null;
    this.running = false;
    this.raf = 0;
    this.busy = false;
    this.lastScan = 0;
    this.detector = null;
    this.mode = null;          // 'native' | 'jsqr'
    this.source = null;        // 'camera' | 'screen' | 'loopback'
    this.loopSeq = [];
    this.loopIndex = 0;
    this.loopInterval = 125;
    this.loopLastSwap = 0;
    this.work = document.createElement('canvas');
    this.workCtx = this.work.getContext('2d', { willReadFrequently: true, alpha: false });
    this.decodes = 0;

    if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
      try {
        this.detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        this.mode = 'native';
      } catch {
        this.detector = null;
      }
    }
    if (!this.detector) this.mode = 'jsqr';
  }

  /** Acquire a source. Pass an existing `stream` to inject one instead of
      acquiring a device — that is how the video branch gets tested without a
      second screen in the room. */
  async start(source, stream = null) {
    if (this.running) await this.stop();
    this.source = source;
    this.decodes = 0;

    if (stream) {
      this.stream = stream;
      this.video.srcObject = stream;
      await this.video.play().catch(() => {});
    } else if (source === 'camera') {
      if (!navigator.mediaDevices?.getUserMedia) throw new Error('no camera API in this context');
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
        audio: false,
      });
      this.video.srcObject = this.stream;
      await this.video.play().catch(() => {});
    } else if (source === 'screen') {
      if (!navigator.mediaDevices?.getDisplayMedia) throw new Error('no screen capture API in this context');
      this.stream = await navigator.mediaDevices.getDisplayMedia({
        video: { frameRate: { ideal: 15 } },
        audio: false,
      });
      this.video.srcObject = this.stream;
      await this.video.play().catch(() => {});
    } else if (source === 'loopback') {
      if (!this.loopSeq.length) throw new Error('loopback has no sequence loaded');
      this.loopIndex = 0;
      this.loopLastSwap = performance.now();
    } else {
      throw new Error(`unknown source: ${source}`);
    }

    this.running = true;
    this.onStatus(`source=${this.source} decoder=${this.mode}`);
    this.tick(performance.now());
    return this.mode;
  }

  loadLoopback(sequence, intervalMs) {
    this.loopSeq = sequence;
    this.loopInterval = intervalMs;
    this.loopIndex = 0;
  }

  tick = (now) => {
    if (!this.running) return;
    if (!this.busy) {
      this.busy = true;
      this.scan(now)
        .catch(() => {})
        .finally(() => { this.busy = false; });
    }
    this.raf = requestAnimationFrame(this.tick);
  };

  async scan(now) {
    let surface = null;

    if (this.source === 'loopback') {
      if (now - this.loopLastSwap >= this.loopInterval) {
        this.loopLastSwap = now;
        this.loopIndex = (this.loopIndex + 1) % this.loopSeq.length;
      }
      const sym = renderSymbol(this.loopSeq[this.loopIndex]);
      surface = sym.canvas;
    } else {
      const vw = this.video.videoWidth;
      const vh = this.video.videoHeight;
      if (!vw || !vh) return;
      const scale = Math.min(1, MAX_DECODE_WIDTH / vw);
      const w = Math.max(1, Math.round(vw * scale));
      const h = Math.max(1, Math.round(vh * scale));
      if (this.work.width !== w || this.work.height !== h) {
        this.work.width = w;
        this.work.height = h;
      }
      this.workCtx.drawImage(this.video, 0, 0, w, h);
      surface = this.work;
    }

    let raw = null;
    if (this.mode === 'native') {
      const hits = await this.detector.detect(surface);
      if (hits && hits.length) raw = hits[0].rawValue;
    } else {
      const img = surface.getContext('2d').getImageData(0, 0, surface.width, surface.height);
      const hit = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
      if (hit && hit.data) raw = hit.data;
    }

    if (raw) {
      this.decodes++;
      this.onFrame(raw);
    }
  }

  async stop() {
    this.running = false;
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
    if (this.stream) {
      for (const t of this.stream.getTracks()) t.stop();
      this.stream = null;
    }
    if (this.video) this.video.srcObject = null;
    this.loopSeq = [];
    this.loopIndex = 0;
  }
}
