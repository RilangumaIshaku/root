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

## Reverse engineering

This cannot be made immune, and no browser app can. Asking for that is asking
for something the platform does not offer.

A web app ships its own program to every visitor so that it can run. The
bundle is on disk the moment the page loads; DevTools shows it, and a text
editor shows the `src/` it was built from. Renaming identifiers, flattening
control flow or splitting strings delays a curious reader for an afternoon.
It does not slow down someone who is actually motivated, and — this is the
part that gets missed — it does not improve your security either, because the
security never depended on the source being unreadable.

What the code being public actually costs you: nothing. The protocol is
AES-GCM over an HKDF-derived key with the frame index in the AAD. That design
is supposed to be public — Kerckhoffs's principle — and publishing it means
people can check the construction instead of trusting it. An attacker who
reads every line still cannot read a single symbol without the handshake,
and the symbols are all they ever see.

What is deliberately done anyway, because it is cheap and honest about what
it is:

- The shipped bundle is minified with no source map. This is a smaller
  handle for casual reading, not a secret. `npm run build:dev` rebuilds it
  unminified.
- No debug handle is installed on a normal load: `window.rootnode` exists
  only under `?debug=1`, so poking at live portal state takes a deliberate
  step rather than a casual one.
- No `eval`, no dynamic `Function` construction, no third-party scripts, no
  CDN — nothing in the bundle can be swapped at runtime.

What is fundamentally not fixable here:

- The plaintext exists in memory while it is on screen. Anything running in
  the page, or in the browser, or on the OS, can read it. A browser cannot
  keep a secret from the machine it is running on.
- Anyone can rebuild the app from source and change it. A modified copy that
  *does* phone home would look like this one at a glance; the tripwires here
  are a claim you can check in your own copy, not a guarantee about someone
  else's.

If reading the source has to become genuinely hard, the source has to stop
being shipped — that means a native shell, not a better obfuscator.

## Development

```
npm install
node test/roundtrip.mjs   # protocol + optical round trip
node build.mjs            # bundle src -> dist/bundle.js
node serve.mjs 4173
```