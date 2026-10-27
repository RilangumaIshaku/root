/* End-to-end proof that a sealed message survives the optical path:
   seal() -> QR modules -> rasterized pixels -> jsQR -> reassembly -> open().
   No browser and no camera required: this is the same pipeline the app runs,
   with a synthetic image standing in for the screen and the lens. */

import jsQR from 'jsqr';
import { seal, sweep, parseFrame, Reassembly, CHUNK_BYTES } from '../src/protocol.js';
import { symbolMatrix } from '../src/sender.js';
import { fingerprint, wipe } from '../src/crypto.js';

let pass = 0;
let fail = 0;

function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  ok   ${name}${detail ? ' — ' + detail : ''}`); }
  else { fail++; console.log(`  FAIL ${name}${detail ? ' — ' + detail : ''}`); }
}

function rasterize(text, scale = 4, quiet = 4) {
  const { size, data } = symbolMatrix(text);
  const side = (size + quiet * 2) * scale;
  const px = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!data[r * size + c]) continue;
      for (let dy = 0; dy < scale; dy++) {
        const y = (r + quiet) * scale + dy;
        for (let dx = 0; dx < scale; dx++) {
          const x = (c + quiet) * scale + dx;
          const o = (y * side + x) * 4;
          px[o] = px[o + 1] = px[o + 2] = 0;
        }
      }
    }
  }
  return { data: px, width: side, height: side };
}

function throughOptics(text) {
  const img = rasterize(text);
  const hit = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
  return hit ? hit.data : null;
}

async function roundTrip(label, message, passphrase) {
  const packet = await seal(message, passphrase);
  const sequence = sweep(packet.trailer, packet.frames);

  // 1. every symbol must survive encode -> pixels -> decode byte-for-byte
  let decoded = 0;
  let worstBytes = 0;
  const payloads = [];
  for (const raw of sequence) {
    worstBytes = Math.max(worstBytes, raw.length);
    const back = throughOptics(raw);
    if (back !== null) decoded++;
    payloads.push(back ?? raw);
  }
  check(`${label}: all ${sequence.length} symbols decode optically`,
    decoded === sequence.length, `${decoded}/${sequence.length}`);

  // 2. density stays in scannable territory (v40/M tops out near 2.3 KB)
  check(`${label}: densest frame is scannable`,
    worstBytes < 400, `${worstBytes} bytes`);

  // 3. reassemble out of order and decrypt
  const asm = new Reassembly();
  const shuffled = [...payloads].reverse();   // receiver joined mid-burst
  for (const p of shuffled) asm.push(p);
  check(`${label}: reassembly complete`, asm.complete,
    `${asm.chunks.size}/${asm.total} frames`);

  const plain = await asm.open(passphrase);
  const text = new TextDecoder().decode(plain);
  wipe(plain);
  check(`${label}: plaintext matches`, text === message,
    text === message ? `${text.length} chars` : JSON.stringify(text.slice(0, 60)));

  // 4. frame count is what chunking promised
  const expected = Math.max(1, Math.ceil(new TextEncoder().encode(message).length / CHUNK_BYTES));
  check(`${label}: chunk count`, packet.total === expected,
    `${packet.total} frames @ ${CHUNK_BYTES} B`);

  return { packet, sequence };
}

async function main() {
  console.log('\n— QR optics —');
  const probe = throughOptics('ROOT//NODE ping 0x5f3a');
  check('plain symbol round-trips', probe === 'ROOT//NODE ping 0x5f3a', String(probe));

  console.log('\n— short message —');
  await roundTrip('short', 'the roof is open. come alone.', 'amber-anvil-arrow-basil-beacon');

  console.log('\n— unicode + long message —');
  await roundTrip(
    'long',
    ' Séance 17 — rendezvous at 03:15. \u{1F512}\n' +
    'Coordinates: 51.5007° N, 0.1246° W. Do not reply on any other channel. '.repeat(6),
    'cobalt-comet-copper-crater-delta',
  );

  console.log('\n— wrong handshake —');
  {
    const packet = await seal('this must not leak', 'correct-horse-battery-staple-x');
    const asm = new Reassembly();
    for (const f of sweep(packet.trailer, packet.frames)) asm.push(f);
    let rejected = false;
    let leaked = null;
    try { leaked = new TextDecoder().decode(await asm.open('wrong-handshake-entirely-y')); }
    catch { rejected = true; }
    check('wrong key is rejected', rejected);
    check('wrong key returns nothing', leaked === null, String(leaked));
  }

  console.log('\n— tampered frame —');
  {
    const packet = await seal('authenticity matters. '.repeat(15), 'quiet-quarry-quartz-radish-raven');
    check('tamper test has >= 3 frames', packet.frames.length >= 3, `${packet.frames.length} frames`);
    const frames = [...packet.frames];
    const victim = JSON.parse(frames[2]);
    victim.p = victim.p.slice(0, -2) + (victim.p.endsWith('AA') ? 'AB' : 'AA');
    frames[2] = JSON.stringify(victim);

    const asm = new Reassembly();
    asm.push(packet.trailer);
    for (const f of frames) asm.push(f);
    let rejected = false;
    try { await asm.open('quiet-quarry-quartz-radish-raven'); } catch { rejected = true; }
    check('modified ciphertext is rejected', rejected);
  }

  console.log('\n— reordered / relabelled frame —');
  {
    const packet = await seal('index binding is not decorative at all. '.repeat(6), 'orbit-papyrus-pebble-pixel-quarry');
    check('reorder test has >= 2 frames', packet.frames.length >= 2, `${packet.frames.length} frames`);
    const frames = packet.frames.map((f) => JSON.parse(f));
    // swap the index labels of frame 0 and frame 1
    [frames[0].i, frames[1].i] = [frames[1].i, frames[0].i];
    const asm = new Reassembly();
    asm.push(packet.trailer);
    for (const f of frames) asm.push(JSON.stringify(f));
    let rejected = false;
    try { await asm.open('orbit-papyrus-pebble-pixel-quarry'); } catch { rejected = true; }
    check('relabelling a frame is rejected', rejected);
  }

  console.log('\n— protocol hygiene —');
  {
    const packet = await seal('x'.repeat(4000), 'signal-slate-summit-tandem-thicket');
    const sequence = sweep(packet.trailer, packet.frames);
    const perPass = packet.total + 1;
    check('sweep is a multiple of passes', sequence.length % perPass === 0,
      `${sequence.length} = ${sequence.length / perPass} passes x ${perPass}`);
    check('trailer leads every pass',
      [...Array(sequence.length / perPass).keys()].every((k) => sequence[k * perPass] === packet.trailer));
    check('worst frame under density cap',
      Math.max(...sequence.map((s) => s.length)) < 900,
      `${Math.max(...sequence.map((s) => s.length))} bytes`);

    check('parseFrame rejects junk', parseFrame('not json') === null);
    check('parseFrame rejects wrong version', parseFrame('{"v":99,"x":"0011223344556677","n":1,"i":0,"p":"AA=="}') === null);
    check('parseFrame rejects bad index', parseFrame('{"v":1,"x":"0011223344556677","n":1,"i":5,"p":"AA=="}') === null);
    check('parseFrame rejects oversized id', parseFrame('{"v":1,"x":"00112233445566","n":1,"i":0,"p":"AA=="}') === null);

    const a = await fingerprint('alpha-bravo-charlie-delta-echo', packet.id);
    const b = await fingerprint('alpha-bravo-charlie-delta-echo', packet.id);
    const c = await fingerprint('alpha-bravo-charlie-delta-foxtrot', packet.id);
    check('fingerprint is deterministic', a === b, a);
    check('fingerprint separates passphrases', a !== c, c);
    check('fingerprint is 48 bits', /^[0-9a-f]{12}$/.test(a), a);
    const g = new Reassembly();
    g.push('{"v":1,"x":"0011223344556677","n":2,"i":0,"p":"AA=="}');
    g.push('{"v":1,"x":"8899aabbccddeeff","n":2,"i":1,"p":"AA=="}');
    check('new transfer id drops the old buffer', g.chunks.size === 1 && g.id === '8899aabbccddeeff');
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
