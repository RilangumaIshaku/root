/* Transmitter: pre-render every symbol in the burst once, then step through
   the sweep on a wall clock driven by requestAnimationFrame so the flash rate
   is tied to display refresh rather than to decode latency. */

import QRCode from 'qrcode';

const QUIET = 4;   // modules of white margin — required for reliable scanning
const SCALE = 8;   // device px per module

/** Encode one frame to its module grid — DOM-free, so tests can rasterize it. */
export function symbolMatrix(text) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  return { size: qr.modules.size, data: qr.modules.data, version: qr.version };
}

/** Render one QR symbol to an offscreen canvas at 1:1 module resolution. */
export function renderSymbol(text) {
  const { size, data } = symbolMatrix(text);
  const side = (size + QUIET * 2) * SCALE;

  const cv = document.createElement('canvas');
  cv.width = side;
  cv.height = side;
  const ctx = cv.getContext('2d', { alpha: false });
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, side, side);
  ctx.fillStyle = '#000000';
  for (let r = 0; r < size; r++) {
    const y = (r + QUIET) * SCALE;
    for (let c = 0; c < size; c++) {
      if (data[r * size + c]) ctx.fillRect((c + QUIET) * SCALE, y, SCALE, SCALE);
    }
  }
  return { canvas: cv, modules: size, side, bytes: text.length };
}

export class Transmitter {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d', { alpha: false });
    this.symbols = [];
    this.order = [];
    this.interval = 125;
    this.raf = 0;
    this.active = false;
    this.step = 0;
    this.onProgress = () => {};
    this.onDone = () => {};
  }

  /** Render the whole sweep up front; a dropped frame during playback then
      costs nothing because no encoding happens mid-flash. */
  load(sequence, intervalMs) {
    this.stop();
    this.symbols = sequence.map((s) => renderSymbol(s));
    this.order = sequence.map((_, i) => i);
    this.interval = intervalMs;
    this.step = 0;
    return {
      count: this.symbols.length,
      modules: this.symbols[0] ? this.symbols[0].modules : 0,
      bytes: this.symbols.reduce((a, s) => a + s.bytes, 0),
    };
  }

  paint(index) {
    const sym = this.symbols[index];
    if (!sym) return;
    const { width, height } = this.canvas;
    this.ctx.fillStyle = '#ffffff';
    this.ctx.fillRect(0, 0, width, height);
    const box = Math.min(width, height) - 16;
    const off = (Math.min(width, height) - box) / 2;
    this.ctx.drawImage(sym.canvas, off, off, box, box);
  }

  start({ onProgress, onDone } = {}) {
    if (this.active || !this.symbols.length) return false;
    this.onProgress = onProgress || this.onProgress;
    this.onDone = onDone || this.onDone;
    this.active = true;
    this.step = 0;
    this.paint(0);
    this.onProgress(0, this.symbols.length);

    let last = performance.now();
    let acc = 0;
    const tick = (now) => {
      if (!this.active) return;
      acc += now - last;
      last = now;
      let advanced = 0;
      while (acc >= this.interval) {
        acc -= this.interval;
        advanced++;
      }
      if (advanced) {
        this.step += advanced;
        if (this.step >= this.symbols.length) {
          this.active = false;
          this.onProgress(this.symbols.length, this.symbols.length);
          this.onDone();
          return;
        }
        this.paint(this.step);
        this.onProgress(this.step, this.symbols.length);
      }
      this.raf = requestAnimationFrame(tick);
    };
    this.raf = requestAnimationFrame(tick);
    return true;
  }

  stop() {
    this.active = false;
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
  }

  destroy() {
    this.stop();
    this.symbols = [];
    this.order = [];
  }
}
