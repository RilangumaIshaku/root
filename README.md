# ROOT//NODE

A one-shot optical messenger. One device flashes a message as a burst of QR
symbols; the other device points a camera at it. No server, no account, no
network — the channel is the screen and the lens.

```
open                 open a portal (generates a handshake)
send <message>       flash the burst, then seal the portal
listen camera        point at the other screen
key <handshake>      open a completed burst
repeat | speed slow  replay / slow the flash
burn                 erase everything held in memory
```

## How it works

The message is split into 80-byte plaintext chunks. Each chunk is sealed with
AES-GCM under a key derived from a shared handshake (HKDF-SHA-256), with the
frame index bound as additional data — a reordered, dropped or spliced frame
is rejected rather than silently accepted. A trailer frame carries the
SHA-256 of the whole plaintext as the final integrity check.

Every symbol in the burst is pre-rendered before playback starts, so no
encoding happens mid-flash. The sequence ping-pongs three times (trailer,
forward, reversed) so a receiver that locks on late still collects the whole
message.

Decoding prefers the native `BarcodeDetector` and falls back to jsQR.

## What this does and does not protect

**It does not make you untraceable, and no browser app can.** Every line of
this code is delivered to the client and can be read by anyone who opens
DevTools. Obfuscating it would be security theatre: the protection here is
that the *ciphertext on screen* is unreadable without the handshake, not that
the *code* is hidden.

What holds up:

- No network egress, no `localStorage`, no cookies, no `indexedDB`, no
  service workers. Each of those is a runtime tripwire that prints a
  violation into the terminal rather than silently succeeding.
- Nothing is persisted. The scrollback never contains message content; a
  decrypted signal sits behind a countdown and then burns.
- One portal carries exactly one message, then seals itself.

What does not hold up:

- A device that is compromised, or a camera app that photographs the screen.
- Traffic analysis: who is holding a phone up at whom is visible to anyone
  in the room, or to anyone watching the network you used to arrange the
  meeting.
- The handshake itself must be passed out of band. If it travels over a
  monitored channel, so does the ability to read everything.

## Development

```
npm install
node test/roundtrip.mjs   # protocol + optical round trip
node build.mjs            # bundle src -> dist/bundle.js
node serve.mjs 4173
```