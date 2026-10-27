/* ROOT//NODE — app shell.

   Rules this file enforces:
     * no network egress for message content, ever
     * no persistent storage of any kind
     * one portal carries exactly one message, then it is sealed
     * received plaintext lives in a panel with a countdown, not in history
*/

import { Transmitter } from './sender.js';
import { Receiver, decodeCanvas } from './receiver.js';
import { Reassembly, seal, sweep, PROTOCOL_VERSION } from './protocol.js';
import { fingerprint, wipe } from './crypto.js';
import { installGuards } from './guard.js';

const $ = (id) => document.getElementById(id);

const el = {
  body: document.body,
  scrollback: $('scrollback'),
  cmdline: $('cmdline'),
  path: $('path'),
  mode: $('meta-mode'),
  clock: $('meta-clock'),
  net: $('meta-net'),
  store: $('meta-store'),
  stageState: $('stage-state'),
  progressTxt: $('progress-txt'),
  progressBar: $('progress-bar').firstElementChild,
  plate: $('plate'),
  plateGlyph: $('plate-glyph'),
  plateTxt: $('plate-txt'),
  plateSub: $('plate-sub'),
  tx: $('tx'),
  rx: $('rx'),
  vid: $('vid'),
  signal: $('signal'),
  signalBody: $('signal-body'),
  signalBurn: $('signal-burn'),
  signalMeta: $('signal-meta'),
  signalBurnNow: $('signal-burn-now'),
  flash: $('flash'),
};

const WORDS = [
  'amber', 'anvil', 'arrow', 'basil', 'beacon', 'bishop', 'bramble', 'cinder',
  'cobalt', 'comet', 'copper', 'crater', 'delta', 'ember', 'fathom', 'fennel',
  'ferry', 'flint', 'garnet', 'granite', 'harbor', 'hazel', 'indigo', 'ivory',
  'jade', 'juniper', 'kelvin', 'kettle', 'lantern', 'lattice', 'ledger', 'lumen',
  'marble', 'meadow', 'meridian', 'nickel', 'nomad', 'obelisk', 'ochre', 'onyx',
  'orbit', 'papyrus', 'pebble', 'pixel', 'quarry', 'quartz', 'radish', 'raven',
  'ripple', 'rustic', 'saffron', 'sapling', 'scarlet', 'sequel', 'signal', 'slate',
  'summit', 'tandem', 'thicket', 'timber', 'trellis', 'umber', 'velvet', 'walnut',
];

const SPEEDS = { slow: 220, normal: 125, fast: 75 };
const SIGNAL_TTL = 60;         // seconds a decrypted signal stays on screen
const MAX_MESSAGE = 4000;

const state = {
  mode: 'idle',                // idle | tx | rx
  speed: 'normal',
  portal: null,                // { id, fp, passphrase, frames, trailer, sealed, seq, passes }
  rx: null,                    // { asm, key, receiver, source, done }
  defaultSource: 'camera',
  burnTimer: 0,
  burnLeft: 0,
  history: [],
};

const transmitter = new Transmitter(el.tx);
const reassembly = new Reassembly();

/* ---------- terminal output ------------------------------------------ */

function log(text, cls = 'sys') {
  for (const chunk of String(text).split('\n')) {
    const p = document.createElement('p');
    p.className = `line ${cls}`;
    p.textContent = chunk;
    el.scrollback.appendChild(p);
  }
  while (el.scrollback.childElementCount > 400) el.scrollback.firstElementChild.remove();
  el.scrollback.scrollTop = el.scrollback.scrollHeight;
}

function banner(lines) {
  log(lines.join('\n'), 'big');
}

function setMode(m) {
  state.mode = m;
  el.mode.textContent = m.toUpperCase();
  el.path.textContent = m === 'tx' ? '~/portal' : m === 'rx' ? '~/channel' : '~';
}

function setStage(text, tone = '') {
  el.stageState.textContent = text;
  el.stageState.className = `val ${tone}`.trim();
}

function setProgress(done, total, label) {
  const pct = total ? Math.round((done / total) * 100) : 0;
  el.progressBar.style.width = `${pct}%`;
  el.progressTxt.textContent = label || (total ? `${done}/${total} · ${pct}%` : 'no carrier');
}

function showPlate(glyph, title, sub) {
  el.plate.hidden = false;
  el.plateGlyph.textContent = glyph;
  el.plateTxt.textContent = title;
  el.plateSub.innerHTML = '';
  el.plateSub.append(sub);
}

function hidePlate() { el.plate.hidden = true; }

function glitch() {
  el.body.classList.remove('glitch', 'on');
  void el.body.offsetWidth;
  el.body.classList.add('glitch');
  el.flash.classList.remove('on');
  void el.flash.offsetWidth;
  el.flash.classList.add('on');
  setTimeout(() => el.body.classList.remove('glitch'), 340);
  setTimeout(() => el.flash.classList.remove('on'), 300);
}

/* ---------- transient signal panel ----------------------------------- */

function showSignal(text, meta) {
  el.signalBody.textContent = text;
  el.signalMeta.textContent = meta;
  el.signal.hidden = false;
  startBurnCountdown(SIGNAL_TTL);
}

function startBurnCountdown(seconds) {
  clearInterval(state.burnTimer);
  state.burnLeft = seconds;
  paintBurn();
  state.burnTimer = setInterval(() => {
    state.burnLeft--;
    paintBurn();
    if (state.burnLeft <= 0) {
      burnSignal('auto-burn complete');
    }
  }, 1000);
}

function paintBurn() {
  const crit = state.burnLeft <= 10;
  el.signalBurn.textContent = `BURN ${String(Math.max(0, state.burnLeft)).padStart(2, '0')}s`;
  el.signalBurn.classList.toggle('crit', crit);
}

function burnSignal(why) {
  clearInterval(state.burnTimer);
  state.burnTimer = 0;
  state.burnLeft = 0;
  if (!el.signal.hidden) {
    // Drop the text node before hiding so it is not left in the DOM.
    el.signalBody.textContent = '';
    el.signal.hidden = true;
    log(`signal destroyed // ${why}`, 'warn');
  }
}

/* ---------- guards ---------------------------------------------------- */

installGuards((what) => {
  log(`!! egress attempt blocked: ${what}`, 'err');
  el.net.innerHTML = 'NET <b>VIOLATION</b>';
  el.net.parentElement.classList.add('warn');
});

/* ---------- transmitter ------------------------------------------------ */

async function openPortal(passphrase) {
  if (state.mode === 'rx') {
    log('channel busy scanning — run `stop` first', 'warn');
    return;
  }
  const phrase = passphrase || makePassphrase();
  const id = provisionalId();
  state.portal = {
    id,
    passphrase: phrase,
    sealed: false,
    seq: null,
    frames: null,
    trailer: null,
    total: 0,
    passes: 3,
    fp: null,
  };
  state.portal.fp = await fingerprint(phrase, id);
  setMode('tx');
  setStage('READY', '');
  showPlate('◍', 'PORTAL OPEN', '');
  el.plateSub.textContent = '';
  setProgress(0, 0, 'awaiting payload');
  renderPortalPlate();
  log('portal opened // volatile only', 'ok');
  log(`transfer id  ${id}`, 'info');
  log(`handshake    ${phrase}`, 'echo');
  log(`verify code  ${state.portal.fp}`, 'info');
  log('give the handshake to the other end out-of-band, then `send <message>`', 'sys');
}

function provisionalId() {
  const a = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

function renderPortalPlate() {
  if (!state.portal) return;
  const sub = document.createElement('div');
  sub.textContent = `id ${state.portal.id} · verify ${state.portal.fp}`;
  el.plateSub.replaceChildren(sub);
}

function makePassphrase() {
  const out = [];
  const buf = crypto.getRandomValues(new Uint32Array(5));
  for (let i = 0; i < 5; i++) out.push(WORDS[buf[i] % WORDS.length]);
  return out.join('-');
}

async function send(text) {
  if (!state.portal) { log('no open portal — run `open` first', 'err'); return; }
  if (state.portal.sealed) { log('portal sealed — one message only. run `open` for a new one.', 'err'); return; }
  if (!text || !text.trim()) { log('empty payload rejected', 'warn'); return; }
  if (text.length > MAX_MESSAGE) { log(`payload exceeds ${MAX_MESSAGE} bytes`, 'err'); return; }

  transmitter.destroy();
  let packet;
  try {
    packet = await seal(text, state.portal.passphrase, state.portal.id);
  } catch (e) {
    log(`seal failed: ${e.message}`, 'err');
    return;
  }

  // `seal` was handed this portal's id, so packet.id === state.portal.id.
  state.portal.fp = packet.fingerprint;
  state.portal.trailer = packet.trailer;
  state.portal.frames = packet.frames;
  state.portal.total = packet.total;

  const sequence = sweep(packet.trailer, packet.frames);
  const perPass = packet.total + 1;
  state.portal.seq = sequence;
  state.portal.passes = sequence.length / perPass;
  let meta;
  try {
    meta = transmitter.load(sequence, SPEEDS[state.speed]);
  } catch (e) {
    log(`encode failed: ${e.message}`, 'err');
    return;
  }

  hidePlate();
  el.tx.hidden = false;
  el.rx.hidden = true;
  setStage('TRANSMITTING', 'live');
  el.body.classList.add('flashing');
  glitch();

  log(`burst armed // ${packet.total} frame(s), ${meta.modules}x${meta.modules} symbol, ${sequence.length} flashes`, 'info');

  // `text` is a local; once this call returns the only copy of the message
  // on this device is the sealed frame set held by the portal.
  await new Promise((resolve) => {
    transmitter.start({
      onProgress: (i, n) => {
        const pass = Math.floor(i / perPass) + 1;
        setProgress(i, n, `flash ${i}/${n} · pass ${pass}/${state.portal.passes || 3}`);
      },
      onDone: () => resolve(),
    });
  });

  el.body.classList.remove('flashing');
  state.portal.sealed = true;
  setStage('SEALED', 'hot');
  setProgress(transmitter.symbols.length, transmitter.symbols.length, 'burst complete');
  glitch();
  showPlate('◍', 'PORTAL SEALED', '');
  renderPortalPlate();
  log('portal sealed // this device now holds only ciphertext', 'ok');
  log('run `repeat` to replay the sealed burst, `burn` to erase the portal', 'sys');
}

function repeatBurst() {
  if (!state.portal || !state.portal.frames) { log('nothing to replay', 'warn'); return; }
  const sequence = state.portal.seq || sweep(state.portal.trailer, state.portal.frames);
  const perPass = state.portal.total + 1;
  transmitter.load(sequence, SPEEDS[state.speed]);
  hidePlate();
  el.tx.hidden = false;
  el.body.classList.add('flashing');
  setStage('TRANSMITTING', 'live');
  glitch();
  transmitter.start({
    onProgress: (i, n) => {
      const pass = Math.floor(i / perPass) + 1;
      setProgress(i, n, `flash ${i}/${n} · pass ${pass}/${sequence.length / perPass}`);
    },
    onDone: () => {
      el.body.classList.remove('flashing');
      setStage('SEALED', 'hot');
      setProgress(sequence.length, sequence.length, 'burst complete');
      showPlate('◍', 'PORTAL SEALED', '');
      renderPortalPlate();
      log('replay complete // plaintext is still destroyed', 'ok');
    },
  });
}

/* ---------- receiver -------------------------------------------------- */

async function listen(source, passphrase) {
  if (state.mode === 'tx' && transmitter.active) {
    log('transmitting — let the burst finish first', 'warn');
    return;
  }
  await stopListening();
  const loopSeq = state.portal?.seq || null;   // captured before the portal dies
  const src = source || state.defaultSource;
  if (state.portal) closePortal('channel handed to receiver');

  reassembly.reset();
  state.rx = {
    asm: reassembly,
    key: passphrase || null,
    done: false,
    source: src,
    receiver: null,
  };
  setMode('rx');
  hidePlate();
  el.tx.hidden = true;
  el.rx.hidden = false;
  setStage('SCANNING', 'live');
  setProgress(0, 0, 'seeking carrier');

  const receiver = new Receiver({
    video: el.vid,
    onFrame: handleFrame,
    onStatus: (s) => log(`receiver // ${s}`, 'sys'),
  });
  state.rx.receiver = receiver;

  if (src === 'loopback') {
    if (!loopSeq) {
      log('loopback needs a sealed portal first — run `send` then `listen loopback`', 'warn');
      await receiver.stop();
      state.rx = null;
      setMode('idle');
      el.rx.hidden = true;
      showPlate('◍', 'PORTAL CLOSED', '');
      setStage('DARK');
      return;
    }
    receiver.loadLoopback(loopSeq, SPEEDS[state.speed]);
  }

  try {
    await receiver.start(src);
  } catch (e) {
    log(`cannot open ${src}: ${e.message}`, 'err');
    if (e.name === 'NotAllowedError') log('permission denied — allow camera/screen access and retry', 'warn');
    setStage('DARK');
    setMode('idle');
    el.rx.hidden = true;
    showPlate('◍', 'PORTAL CLOSED', '');
    state.rx = null;
    return;
  }

  log(`listening // ${src}. point it at the flashing portal.`, 'ok');
  if (state.rx.key) log('handshake supplied — will decrypt on completion', 'info');
}

function handleFrame(raw) {
  const rx = state.rx;
  if (!rx || rx.done) return;
  const changed = rx.asm.push(raw);
  if (rx.asm.id) {
    setProgress(rx.asm.chunks.size, rx.asm.total,
      `packets ${rx.asm.chunks.size}/${rx.asm.total || '?'} · lock ${rx.asm.id}`);
    setStage(rx.asm.trailer ? 'LOCKED' : 'SYNC', rx.asm.trailer ? 'live' : 'live');
  }
  if (!changed) return;

  if (rx.asm.complete) {
    rx.done = true;
    log(`burst complete // ${rx.asm.total} packet(s) verified present`, 'ok');
    openReceived();
  }
}

async function openReceived() {
  const rx = state.rx;
  if (!rx) return;
  if (!rx.key) {
    setStage('SEALED', 'hot');
    log('burst held. run `key <handshake>` to open it.', 'warn');
    return;
  }
  try {
    const plain = await rx.asm.open(rx.key);
    const text = new TextDecoder().decode(plain);
    wipe(plain);
    const fp = await fingerprint(rx.key, rx.asm.id);
    rx.asm.reset();                       // ciphertext no longer needed
    await stopListening();
    setStage('DELIVERED', 'hot');
    setProgress(1, 1, 'signal received');
    showSignal(text, `verify ${fp}`);
    log('signal decrypted // contents are not written to history', 'ok');
    log('it burns on the timer — `burn` destroys it now', 'sys');
  } catch (e) {
    log(`open failed // ${e.message}`, 'err');
    log('wrong handshake or damaged burst — packet retained, try another `key`', 'warn');
    setStage('REJECTED', 'hot');
    rx.done = false;                      // allow a retry
  }
}

async function stopListening() {
  if (state.rx?.receiver) await state.rx.receiver.stop();
}

/* ---------- teardown -------------------------------------------------- */

function closePortal(why) {
  transmitter.stop();
  transmitter.destroy();
  if (state.portal) {
    wipe(state.portal.passphrase);
    state.portal = null;
  }
  el.tx.hidden = true;
  el.body.classList.remove('flashing');
  setStage('DARK');
  setProgress(0, 0, 'no carrier');
  showPlate('◍', 'PORTAL CLOSED', '');
  if (why) log(`portal closed // ${why}`, 'warn');
  if (state.mode === 'tx') setMode('idle');
}

async function burnAll(reason = 'manual burn') {
  clearInterval(state.burnTimer);
  state.burnTimer = 0;
  state.burnLeft = 0;
  el.signalBody.textContent = '';
  el.signal.hidden = true;

  await stopListening();
  if (state.rx) {
    state.rx.asm.reset();
    state.rx = null;
  }
  closePortal('');
  reassembly.reset();
  setMode('idle');
  el.rx.hidden = true;
  el.tx.hidden = true;
  showPlate('◍', 'PORTAL CLOSED', '');
  log(`everything erased // ${reason}`, 'warn');
}

/* ---------- commands -------------------------------------------------- */

const COMMANDS = {
  help() {
    banner([
      'ROOT//NODE — one-shot optical messenger',
      '',
      'TRANSMIT   open [handshake]   open a portal (generates a handshake if omitted)',
      '           send <message>     flash the message as a QR burst, then seal',
      '           repeat             replay the sealed burst (ciphertext only)',
      '',
      'RECEIVE    listen [camera|screen|loopback] [handshake]',
      '           key <handshake>    open a completed burst',
      '           stop               close the camera',
      '',
      'CONTROL    speed slow|normal|fast    flash rate (220 / 125 / 75 ms)',
      '           status | clear | burn | help',
      '',
      'Nothing is written to disk, cookies or storage. There is no history:',
      'a decrypted signal stays on screen until its timer runs out.',
    ]);
  },

  async open(args) {
    await openPortal(args.trim() || null);
  },

  async send(args) {
    await send(args);
  },

  repeat() { repeatBurst(); },

  async listen(args) {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    let source = null;
    let key = null;
    if (parts.length && ['camera', 'screen', 'loopback'].includes(parts[0])) {
      source = parts.shift();
    }
    if (parts.length) key = parts.join(' ');
    await listen(source, key);
  },

  async key(args) {
    const phrase = args.trim();
    if (!state.rx) { log('no burst buffered — run `listen` first', 'err'); return; }
    if (!phrase) { log('usage: key <handshake>', 'warn'); return; }
    state.rx.key = phrase;
    if (!state.rx.asm.complete) {
      log(`burst incomplete — ${state.rx.asm.chunks.size}/${state.rx.asm.total || '?'} frames, keep scanning`, 'warn');
      return;
    }
    state.rx.done = true;
    await openReceived();
  },

  async stop() {
    await stopListening();
    if (state.rx) state.rx.asm.reset();
    state.rx = null;
    setMode('idle');
    el.rx.hidden = true;
    showPlate('◍', 'PORTAL CLOSED', '');
    setStage('DARK');
    setProgress(0, 0, 'no carrier');
    log('channel closed', 'warn');
  },

  source(args) {
    const s = args.trim();
    if (!['camera', 'screen', 'loopback'].includes(s)) {
      log('usage: source camera|screen|loopback', 'warn');
      return;
    }
    state.defaultSource = s;
    if (state.rx) state.rx.source = s;
    log(`source default set to ${s}`, 'info');
  },

  speed(args) {
    const s = args.trim();
    if (!SPEEDS[s]) { log('usage: speed slow|normal|fast', 'warn'); return; }
    state.speed = s;
    log(`flash interval ${SPEEDS[s]}ms`, 'info');
  },

  status() {
    const lines = [
      `protocol    v${PROTOCOL_VERSION}`,
      `mode        ${state.mode}`,
      `speed       ${state.speed} (${SPEEDS[state.speed]} ms/frame)`,
      `decoder     ${state.rx?.receiver ? state.rx.receiver.mode : 'n/a'}`,
      `source      ${state.rx?.source || 'n/a'}`,
      `portal      ${state.portal ? `${state.portal.id} ${state.portal.sealed ? 'SEALED' : 'OPEN'}` : 'closed'}`,
      `buffered    ${reassembly.id ? `${reassembly.chunks.size}/${reassembly.total}` : 'empty'}`,
      `persistent  none`,
      `network     none (guarded)`,
    ];
    log(lines.join('\n'), 'info');
  },

  clear() { el.scrollback.replaceChildren(); },

  burn() { burnAll(); },

  wipe() { burnAll(); },
};

function run(raw) {
  const line = raw.trim();
  if (!line) return;
  const sp2 = line.indexOf(' ');
  const cmd = (sp2 === -1 ? line : line.slice(0, sp2)).toLowerCase();
  const args = sp2 === -1 ? '' : line.slice(sp2 + 1);

  // Message content must never be echoed into the scrollback — the log only
  // ever holds system lines.
  if (cmd === 'send') {
    log(`root@node:~$ send <${args.length} bytes, withheld>`, 'echo');
  } else {
    log(`root@node:~$ ${line}`, 'echo');
  }
  // The handshake is fair game to remember; a message payload never is.
  if (cmd !== 'send') state.history.push(line);
  const fn = COMMANDS[cmd];
  if (!fn) {
    log(`command not found: ${cmd} — try \`help\``, 'err');
    return;
  }
  const out = fn(args);
  if (out && typeof out.catch === 'function') {
    out.catch((e) => {
      log(`error // ${e.message}`, 'err');
      console.error(e);
    });
  }
}

el.cmdline.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const v = el.cmdline.value;
    el.cmdline.value = '';
    run(v);
  }
});

el.signalBurnNow.addEventListener('click', () => burnSignal('manual burn'));

/* ---------- clock ------------------------------------------------------ */

setInterval(() => {
  el.clock.textContent = new Date().toTimeString().slice(0, 8);
}, 1000);
el.clock.textContent = new Date().toTimeString().slice(0, 8);

window.addEventListener('beforeunload', () => {
  transmitter.destroy();
  state.rx?.receiver?.stop();
  wipe(state.portal?.passphrase);
});

/* ---------- boot ------------------------------------------------------- */

const BOOT = [
  'ROOT//NODE  build 0.4.1   protocol v' + PROTOCOL_VERSION,
  'mounting volatile store ......... ok',
  'persistent storage .............. none',
  'network egress .................. disabled',
  'optical channel ................. ready',
  '',
];

async function boot() {
  let i = 0;
  const type = () => {
    if (i < BOOT.length) {
      log(BOOT[i], i === 0 ? 'big' : 'sys');
      i++;
      setTimeout(type, i === 1 ? 140 : 70);
      return;
    }
    el.body.classList.remove('boot');
    el.body.classList.add('ready');
    log('type `help` for commands, `open` to transmit, `listen` to receive', 'info');
    el.cmdline.focus();
  };
  type();
}

boot();

/* Console hook: lets you drive the terminal and decode a painted symbol from
   devtools. It exposes no network and no storage surface. */
window.rootnode = { state, run, transmitter, reassembly, decodeCanvas, Reassembly, Receiver, seal, sweep };
